Configuration DcConfig
{
	[CmdletBinding()]

	Param
	(
		[string]$NodeName = 'localhost',
		[Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
		[PSCredential]$DomainAdminCredentials,
        [string]$DomainName,
		[string]$NetBiosDomainname,
		[string]$ForwarderIPaddress,
		[string]$ForwarderDomain,
		[string]$TimeZone

	)

	Import-DscResource -ModuleName PSDesiredStateConfiguration, ActiveDirectoryDsc
	Import-DscResource -ModuleName ComputerManagementDsc -ModuleVersion 8.4.0
	


	Node $nodeName
	{             
  		LocalConfigurationManager
		{
			ConfigurationMode = 'ApplyAndAutoCorrect'
			RebootNodeIfNeeded = $true
			ActionAfterReboot = 'ContinueConfiguration'
			AllowModuleOverwrite = $true
		}
		TimeZone TimeZoneExample
        {
			isSingleInstance = 'Yes'
            TimeZone = $TimeZone

        }

		WindowsFeature DNS_RSAT
		{ 
			Ensure = "Present" 
			Name = "RSAT-DNS-Server"
		}

		WindowsFeature ADDS_Install 
		{ 
			Ensure = 'Present' 
			Name = 'AD-Domain-Services' 
		} 

		WindowsFeature RSAT_AD_AdminCenter 
		{
			Ensure = 'Present'
			Name   = 'RSAT-AD-AdminCenter'
		}

		WindowsFeature RSAT_ADDS 
		{
			Ensure = 'Present'
			Name   = 'RSAT-ADDS'
		}

		WindowsFeature RSAT_AD_PowerShell 
		{
			Ensure = 'Present'
			Name   = 'RSAT-AD-PowerShell'
			DependsOn = '[ADDomain]CreateForest'
		}

		WindowsFeature RSAT_AD_Tools 
		{
			Ensure = 'Present'
			Name   = 'RSAT-AD-Tools'
		}

		WindowsFeature RSAT_Role_Tools 
		{
			Ensure = 'Present'
			Name   = 'RSAT-Role-Tools'
		}
		ADDomain CreateForest 
		{ 
			DomainName = $NetBiosDomainname            
			Credential = $DomainAdminCredentials
			SafemodeAdministratorPassword = $DomainAdminCredentials
            ParentDomainName = $DomainName
			DependsOn =  '[WaitForADDomain]DscForestWait'
		}

	 WaitForADDomain DscForestWait
        {
            DomainName = $DomainName
            DependsOn =  '[WindowsFeature]ADDS_Install'
			WaitTimeout = 3600
			WaitForValidCredentials = $true
			Credential = $DomainAdminCredentials
            
        }
		
	}
}