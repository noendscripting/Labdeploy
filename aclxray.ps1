<#
    This code is Copyright (c) 2017 Microsoft Corporation.

    All rights reserved.
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
    INCLUDING BUT NOT LIMITED To THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.'

    IN NO EVENT SHALL MICROSOFT AND/OR ITS RESPECTIVE SUPPLIERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR 
    CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
    WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
    WITH THE USE OR PERFORMANCE OF THIS CODE OR INFORMATION.

.SYNOPSIS

  Script deploys a test lab for AclXray including 4 VMs.

.DESCRIPTION
  
    This will deploy a new resource group with a new VNET called ACLXRAYlabvnet with IP range 10.6.0.0/24, a new storage account 4 Vms and a Lodablancer with inbound NAT for RDP. The VM names are: contosodc1, contosofs1, fabrikamdc1, fabrikamfs1.
    all resources are deployed to EASTUS. Script will attempt to identify your public IP address to configure Network Security Group for RDP access. 


.PARAMETER   vmsize
Sets the vm sizes for all vms (Default 'standard_B2s')
.PARAMETER    region 
Sets deployment region (Default 'eastus')
.PARAMETER    rg
Sets Resource Group name.
.PARAMETER    shutdownTimeZone
Sets time zone for shutdown schedduler and a local time zone for servers. 
.PARAMETER    vnetname
Name of the VNET for the lab. (Default 'ACLXRAYlabvnet')
.PARAMETER   containerName
Name of the container where uploaded artifacts are going to be stored (Default 'storageartifacts')



.INPUTS
   The script will ask for credentials. These are the credentials for your azure subscription, not the VMs. VM creds are already set.

.NOTES
  Version:        11.0
  Author:         Mike Resnick Microsoft
  Creation Date: 02/11/2021


 
#This is for internal Microsoft use only

#>
#Requires -Modules @{ ModuleName="ActiveDirectoryDsc"; ModuleVersion="6.0.1"}
#Requires -Modules @{ ModuleName="PSDscResources"; ModuleVersion="2.12.0.0"}

[CmdletBinding()]
  
Param(
  [string]$vmsize = 'Standard_B2s',
  [string]$region = 'eastus',
  [Parameter(
    Mandatory = $true,
    HelpMessage = "Enter name of the Resource Group where lab is going to be deployed'nIf you enter existing name contents of resoucre group may be overwritten."
  )
  ]
  [string]$RG,
  [string]$shutdownTimeZone ,
  [string]$shutDownTime = '01:00',
  [string]$vnetname = 'ACLXRAYlabvnet',
  [string]$containerName = "storageartifacts"

)


if ($VerbosePreference -ne 'Continue') {
  $InformationPreference = 'Continue'

}
Write-Information "Running in non-verbose mode"

$currentUser = Get-AzContext
if ([string]::IsNullOrEmpty($currentUser)) {
  Login-AzAccount
  $currentUser = Get-AzContext

}
#region Public IP address
Write-Host "Identifying your current public IP address"
$currentPublicIP = (Invoke-WebRequest https://api.ipify.org -ErrorAction SilentlyContinue -ErrorVariable errorData ).Content
if (![string]::IsNullOrEmpty($errorData)) {
  Write-Warning "Unable to find your public IP address. Please verify your external IP and enter at the prompt below"
  $currentPublicIP = Read-Host "Please enter your public IP address"
  if ([string]::IsNullOrEmpty($currentPublicIP)) {
    Write-Error "Public IP address empty, can not continue. Terminating script"
    exit
  }
}
Write-Host "Your current public IP address is: $($currentPublicIP)"
#endregion

Write-Host "Identifying your current time zone"
$currentTimeZone = (Get-TimeZone).id
if (!($shutdownTimeZone)) {
  $shutdownTimeZone = $currentTimeZone
}

Write-Host "Setting lab VMs time zone to $($shutdownTimeZone)"
#Region verifying deployimnet subscription
$title = 'ACLXRAY Lab deployment'
$message = "You are about to deploy 4 VMs into subscription ""$($currentUser.Subscription.Name)""`nDo you want to proceed?"
$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes"
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No"
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
$resultSubscription = $host.ui.PromptForChoice($title, $message, $options, 0) 
switch ($resultSubscription) {     
  1 {
    #select desired subscription or cancel 
    Write-Host 'Pick from the list of subscriptions available to you:'
    Get-AzSubscription | Select-Object name | Out-Host
    [string]$subscription = Read-Host "Please type subscription name in the box below.`nPress enter if you want to exit the srcipt"
    if ([string]::IsNullOrEmpty($subscription)) {
      Write-Host 'Operation canceled.Ending script'
      Exit
    }
    else {
      Select-AzSubscription -SubscriptionName $subscription
    }
  }
}
#endregion

#region Create Resource Group, Storage Account and Container

Get-AzResourceGroup -Name $RG -ErrorAction SilentlyContinue -ErrorVariable errorData | Out-Null

#verifying existing Resource Group 
if ([string]::IsNullOrEmpty($errorData)) {
  $title = "ACLXRAY Lab deployment"
  $message = "You are about to deploy ACLXRAYLAB into existing Resource Group $($RG)""`nThis may overwrite existing ACLXRAYLab deployment""`nDo you want to proceed?"
  $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes"
  $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No"
  $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
  $resultResourceGroup = $host.ui.PromptForChoice($title, $message, $options, 0) 
  switch ($resultResourceGroup) {
    1 {
      $RG = Read-Host "Enter New Resource Group Name`nPress enter if you want to exit the script"
      if ([string]::IsNullOrEmpty($RG)) {
        Write-Host "Operation canceled.Ending script" 
        Exit
      }

    }

  }
}
else {
  Write-Host "Creating Resource Group $($RG)"
  New-AzResourceGroup -Name $RG -Location $region -Force
}
$randomprefix = get-random -Minimum 1000 -Maximum 10000000
Write-Host "Generated random prefix $($randomprefix)"
#create storage account
$storageAccountName = 'aclxray' + $randomprefix
Write-Host "Creating storage account name $($storageAccountName)"
$storageAccount = New-AzStorageAccount -ResourceGroupName $RG -Name $storageAccountName -Location $region -type Standard_LRS


#create container and generate SAS tokens to copy files from source to newly created storage account
Write-Host "Creating container $($containerName) for artifact data"
New-AzStorageContainer -Name $containerName -Context $storageAccount.context  | Out-Null
$destcontext = $storageAccount.context
Write-Host "Obtaining SAS token for arctifact container $($containerName)"
$destSASToken = New-AzStorageContainerSASToken -Context $destcontext -ExpiryTime (get-date).AddHours(4).ToUniversalTime() -Name $containerName -Permission racwdl
$artifactSASTokenSecure = ConvertTo-SecureString -String $destSASToken -AsPlainText -Force 
$artifactLocation = "$($destcontext.BlobEndPoint)$($containerName)"
Write-Verbose "Destination SAA $($destSAStoken)"
#endregion
#region publishing DSC package data

$DSConfigPath = "$($PSScriptRoot)\DSC\DCConfig.ps1"


Write-Host "Publishing DConfig DSC package"
$DSConfigURI = Publish-AzVMDscConfiguration -ResourceGroupName $RG -ConfigurationPath $DSConfigPath -StorageAccountName $storageAccountName -ContainerName $containerName -Force
$DSConfigFile = $DSConfigURI.Split("/")[-1]
Write-Host "Succcessfully published DSC config file $($DSConfigFile)"
#endregion
#region uplaoding custom script extension artifacts
Write-Verbose "Artifacts location $($ArtifactLocation)"
Write-Host "Copying custom script artifacts"
Get-ChildItem .\CustomScripts | ForEach-Object {
  Write-Host "Copying file $($_.Name)"
  Set-AzStorageBlobContent -File $_.FullName -Blob $_.FullName.Substring((Get-Item $PSScriptRoot).FullName.Length + 1) -Context $destcontext -Container $containerName -Force | Out-Null

}
$templatefile = '.\azuredeploy.json'



$DeployParameters = @{
  "Name"                       = "ACLXRALAB_$(get-date -UFormat %Y_%m_%d-%I-%M-%S%p)"
  "ResourceGroupName"          = $RG
  "TemplateFile"               = $templatefile
  "virtualMachineSize"         = $vmsize
  "virtualNetworkName"         = $vnetname
  "shutdownTimeZone"           = $shutdownTimeZone
  "shutDownTime"               = $shutDownTime
  "_artifactsLocation"         = $ArtifactLocation
  "_artifactsLocationSasToken" = $artifactSASTokenSecure 
  "DCConfigArchiveFileName"    = $DSConfigFile
  "currentPublicIp"            = $currentPublicIP

}


$deployResults = New-AzResourceGroupDeployment @DeployParameters -Verbose
if ($deployResults.ProvisioningState -eq 'Succeeded') {

  Write-Host "Deleting storage $($storageAccountName)"

  $storageAccount | Remove-AzStorageAccount -Force

  write-host "Completed deploying ACLXRAY lab"
}