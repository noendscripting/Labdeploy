Configuration DcConfig
{
	[CmdletBinding()]

	Param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullorEmpty()]
		[PSCredential]$DomainAdminCredentials,
		[string]$DomainName,
		[string]$NetBiosDomainname,
		[string]$ForwarderIPaddress,
		[string]$ForwarderDomain,
		[string]$TimeZone

	)

	Import-DscResource -ModuleName PSDscResources
	Import-DscResource -ModuleName ActiveDirectoryDsc

	

	Node 'localhost'
	{             
		LocalConfigurationManager {
			ConfigurationMode    = 'ApplyAndAutoCorrect'
			RebootNodeIfNeeded   = $true
			ActionAfterReboot    = 'ContinueConfiguration'
			AllowModuleOverwrite = $true
		}
		WindowsFeatureSet ADDS_Features
		{
			Name = @('RSAT-DNS-Server','AD-Domain-Services','RSAT-AD-AdminCenter','RSAT-ADDS','RSAT-AD-PowerShell','RSAT-AD-Tools','RSAT-Role-Tools')
			Ensure = 'Present'
		}	
		ADDomain CreateForest { 
			DomainName                    = $DomainName            
			Credential                    = $DomainAdminCredentials
			SafemodeAdministratorPassword = $DomainAdminCredentials
			DomainNetbiosName             = $NetBiosDomainname
			DependsOn                     = '[WindowsFeatureSet]ADDS_Features'
		}

		WaitForADDomain LocalForestWait {
			DomainName              = $DomainName
			DependsOn               =  '[ADDomain]CreateForest'
			WaitTimeout             = 3600
			WaitForValidCredentials = $true
			Credential              = $DomainAdminCredentials
			RestartCount            = 5 
            
		}
		#create user OUs
		ADOrganizationalUnit UserAccountsOU
		{
			Name="User Accounts"
			Path="dc=$($NetBiosDomainname),dc=com"
			Ensure = "Present"
			DependsOn = '[WaitForADDomain]LocalForestWait'
		}
		ADOrganizationalUnit EnabledUsersOU
		{
			Name="Enabled Users"
			Path="OU=User Accounts,dc=$($NetBiosDomainname),dc=com"
			Ensure = "Present"
			DependsOn =   '[ADOrganizationalUnit]UserAccountsOU'
		}

		#create Group OUs
		ADOrganizationalUnit GroupsOU
		{
			Name="Groups"
			Path="dc=$($NetBiosDomainname),dc=com"
			Ensure = "Present"
			DependsOn =   '[WaitForADDomain]LocalForestWait'
		}
		ADOrganizationalUnit SecurityGroupsOU
		{
			Name="Security Groups"
			Path="OU=Groups,dc=$($NetBiosDomainname),dc=com"
			Ensure = "Present"
			DependsOn =   '[ADOrganizationalUnit]GroupsOU'
		}
		Script SetForwarders {
			TestScript = 
			{
			 $result = $null
			 $result = (Get-DnsServerZone -Name $using:ForwarderDomain -ErrorAction SilentlyContinue)
				if ($result -eq $null) {
					return $false
				}
				else {
					return $true
				}

		  
			}
			GetScript  =
			{
				$TestResult = Test-ADDSDomainControllerInstallation -DomainName $using:domainname -SafeModeAdministratorPassword $using:DomainAdminCredentials.Password -Credential $using:DomainAdminCredentials
				if ($testresult.status -notcontains "Error") {
					$results = @{"domain" = $True }
				}
				else {
					$results = @{"domain" = $false }
				}
				return $results
			}
			SetScript  = 
			{
				Add-DnsServerConditionalForwarderZone -MasterServers $using:ForwarderIPaddress -Name $using:ForwarderDomain
		  
			}
			Dependson  = '[WaitForADDomain]LocalForestWait'
		}
		WaitForADDomain RemoteForestWait {
			DomainName              = $ForwarderDomain
			DependsOn               = '[Script]SetForwarders'
			WaitTimeout             = 3600
			WaitForValidCredentials = $true
			Credential              = $DomainAdminCredentials
			RestartCount            = 5 
            
		}
		ADDomainTrust SetTrust {
			Ensure               = "Present"
			SourceDomainName     = $DomainName
			TargetDomainName     = $ForwarderDomain
			TargetCredential     = $DomainAdminCredentials
			TrustType            = "Forest"
			TrustDirection       = "Outbound"
			Dependson            = '[WaitForADDomain]RemoteForestWait'
			AllowTrustRecreation = $true
		}
		
		
	}
}