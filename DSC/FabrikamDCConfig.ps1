Configuration DcConfig
{
	[CmdletBinding()]

	Param
	(
		[string]$NodeName = 'localhost',
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
	Import-DscResource -ModuleName ComputerManagementDsc
	Import-DscResource -ModuleName ActiveDirectoryDsc

	Node $nodeName
	{             
		LocalConfigurationManager {
			ConfigurationMode    = 'ApplyAndAutoCorrect'
			RebootNodeIfNeeded   = $true
			ActionAfterReboot    = 'ContinueConfiguration'
			AllowModuleOverwrite = $true
		}
		TimeZone TimeZoneExample {
			isSingleInstance = 'Yes'
			TimeZone         = $TimeZone

		}
		WindowsFeatureSet ADDS_Features
		{
			Name = @('RSAT-DNS-Server','AD-Domain-Services','RSAT-AD-AdminCenter','RSAT-ADDS','RSAT-AD-PowerShell','RSAT-AD-Tools','RSAT-Role-Tools')
			Ensure = 'Present'
		}

		<#WindowsFeature DNS_RSAT { 
			Ensure = "Present" 
			Name   = "RSAT-DNS-Server"
		}

		WindowsFeature ADDS_Install { 
			Ensure = 'Present' 
			Name   = 'AD-Domain-Services' 
		} 

		WindowsFeature RSAT_AD_AdminCenter {
			Ensure = 'Present'
			Name   = 'RSAT-AD-AdminCenter'
		}

		WindowsFeature RSAT_ADDS {
			Ensure = 'Present'
			Name   = 'RSAT-ADDS'
		}

		WindowsFeature RSAT_AD_PowerShell {
			Ensure = 'Present'
			Name   = 'RSAT-AD-PowerShell'
		}

		WindowsFeature RSAT_AD_Tools {
			Ensure = 'Present'
			Name   = 'RSAT-AD-Tools'
		}
	

		WindowsFeature RSAT_Role_Tools {
			Ensure = 'Present'
			Name   = 'RSAT-Role-Tools'
		}#>
		
		

		
		ADDomain CreateForest { 
			DomainName                    = $DomainName            
			Credential                    = $DomainAdminCredentials
			SafemodeAdministratorPassword = $DomainAdminCredentials
			DomainNetbiosName             = $NetBiosDomainname
			DependsOn                     = '[WindowsFeatureSet]ADDS_Features'
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
			TrustDirection       = "Bidirectional"
			Dependson            = '[WaitForADDomain]DscForestWait'
			AllowTrustRecreation = $true
		}
		
		
	}
}