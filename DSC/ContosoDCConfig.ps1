Configuration DcConfig
{
	[CmdletBinding()]

	Param
	(
		[string]$NodeName = 'localhost',
		[Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
		[PSCredential]$DomainAdminCredentials,
		[pscredential]$SafemodeAdministrator,
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
  		LocalConfigurationManager
		{
			ConfigurationMode = 'ApplyAndAutoCorrect'
			RebootNodeIfNeeded = $true
			ActionAfterReboot = 'ContinueConfiguration'
			AllowModuleOverwrite = $true
		}
		TimeZone TimeZone
        {
			isSingleInstance = 'Yes'
            TimeZone = $TimeZone

        }
		WindowsFeatureSet ADDS_Features
		{
			Name = @('RSAT-DNS-Server','AD-Domain-Services','RSAT-AD-AdminCenter','RSAT-ADDS','RSAT-AD-PowerShell','RSAT-AD-Tools','RSAT-Role-Tools')
			Ensure = 'Present'
		}
		
		ADDomain CreateForest 
		{ 
			DomainName = $DomainName           
			Credential = $DomainAdminCredentials
			SafemodeAdministratorPassword = $SafemodeAdministrator
			DependsOn =  '[WindowsFeatureSet]ADDS_Features'
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

		
	}
}