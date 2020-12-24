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

	$groupList = @(
		"Logistics",
		"Information Technology",
		"IT Support",
		"Strategic Information Systems",
		"Data Entry",
		"Research and Development",
		"Strategic Sourcing",
		"Purchasing",
		"Operations",
		"Public Relations",
		"Corporate Communications",
		"Advertising Market Research",
		"Strategic Marketing",
		"Customer Service",
		"Telesales",
		"Account Management",
		"Marketing",
		"Sales",
		"Payroll",
		"Recruitment",
		"Training",
		"Human Resource",
		"Accounting",
		"Finance"
	)

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

		#create user OUs
		ADOrganizationalUnit UserAccuntsOU
		{
			Name="User Accounts"
			Path="dc=$($NetBiosDomainname),dc=com"
			Ensure = "Present"
			DependsOn =   '[ADDomain]CreateForest'
		}
		ADOrganizationalUnit EnabledUsersOU
		{
			Name="Enabled Users"
			Path="OU=User Accounts,dc=$($NetBiosDomainname),dc=com"
			Ensure = "Present"
			DependsOn =   '[ADOrganizationalUnit]UserAccuntsOU'
		}

		#create Group OUs
		ADOrganizationalUnit GroupsOU
		{
			Name="Groups"
			Path="dc=$($NetBiosDomainname),dc=com"
			Ensure = "Present"
			DependsOn =   '[ADDomain]CreateForest'
		}
		ADOrganizationalUnit SecurityGroupsOU
		{
			Name="Security Groups"
			Path="OU=Groups,dc=$($NetBiosDomainname),dc=com"
			Ensure = "Present"
			DependsOn =   '[ADOrganizationalUnit]GroupsOU'
		}

		foreach ($group in $groupList) {
			ADGroup $group
			{
				GroupName = $group
				DisplayName = $group
				GroupScope = "Global"
				Category = "Security"
				Path = "OU=Security Groups,OU=Groups,dc=$($NetBiosDomainname),dc=com"
				Ensure = "Present"
				Dependson  = '[ADOrganizationalUnit]SecurityGroupsOU'
			}
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
			Dependson  = '[ADDomain]CreateForest'
		}
		WaitForADDomain DscForestWait {
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
			Dependson            = '[WaitForADDomain]DscForestWait'
			AllowTrustRecreation = $true
		}
		
		
	}
}