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

  Script deploys a test lab for AclXray including 6 VMs. Use your internal azure subscription to deploy this. 

.DESCRIPTION
  
    This will deploy a new resource group called ACLXRAYLAB with a new VNET called ACLXRAYlabvnet on 10.6.0.0/24. It will then create a new storage account,use ARM template to deploy the lab VMs on basic_a1 size to the new vnet/rg. The VM names are: contosodc1, contosoex1, contosofs1, fabrikamdc1, fabrikamfs1, eucontosodc1, eufs1
    all resources are deployed to EASTUS


.PARAMETER   vmsize
             Sets the vm sizes for all vms (standard_B2s is default)
.PARAMETER    region 
             Sets deployment region (eastus is default)
.PARAMETER    rg
             Sets resourcegroup name. (ACLXRAYLAB is default)
.PARAMETER    shutdownTimeZone
             Sets time zone for shutdown schedduler and a local time zone for servers. (Default EasternTime Zone)
.PARAMETER    vnetname
             Name of the VNET for the lab. (Default 'ACLXRAYlabvnet')



.INPUTS
   The script will ask for credentials. These are the credentials for your azure subscription, not the VMs. VM creds are already set.

.NOTES
  Version:        10.0
  Author:         Mike Resnick Microsoft
  Creation Date: 10/4/2020

 
#This is for internal Microsoft use only

#>
#Requires -Modules Az,PSDesiredStateConfiguration,ActiveDirectoryDsc,ComputerManagementDsc,StorageDsc

[CmdletBinding()]
  
Param(
  $vmsize = 'Standard_B2s',
  $region = 'eastus',
  $RG = 'ACLXRAYLAB',
  $shutdownTimeZone = 'Eastern Standard Time',
  $shutDownTime = '01:00',
  $vnetname = 'ACLXRAYlabvnet',
  $containerName = "storageartifacts"

)





$currentContext = Get-AzContext 
if ([string]::IsNullOrEmpty($currentContext)) {
  Login-AzAccount

}

#Region verifying deployimnet subscription
$title = "ACLXRAY Lab deployment"
$message = "You are about to deploy 6 VMs into subscription ""$($currentContext.Subscription.Name)""`nDo you want to proceed?"
$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes"
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No"
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
$result = $host.ui.PromptForChoice($title, $message, $options, 0) 
switch ($result)
{     
  1{
    #select desired subscription or cancel 
    Write-Host "Pick from the list of subscriptions available to you:"
    Get-AzSubscription | Select-Object name | Out-Host
    [string]$subscription = Read-Host "Please type subscription name in the box below.`nPress enter if you want to exit the srcipt"
    if ([string]::IsNullOrEmpty($subscription))
    {
     Write-Host "Operation canceled.Ending script" 
     Exit
    }
    else {
      Select-AzSubscription -SubscriptionName $subscription
    }
  }
}
#endregion

#-----------------------------------------------



#region Create Resource Group, Storage Account and Container


Get-AzResourceGroup -Name $RG -ErrorAction SilentlyContinue -ErrorVariable errorData | Out-Null
#testing mode 
if ([string]::IsNullOrEmpty($errorData) -and $VerbosePreference -eq "Continue")
{
  write-Verbose "Testing phase reusing existing storage"
  $storageAccount = (Get-AzStorageAccount -ResourceGroupName $RG  | Where-Object {$_.StorageAccountName -like "aclxray*"})[0]
  $storageAccountName = $storageAccount.StorageAccountName
 
}
else {
  New-AzResourceGroup -Name $RG -Location $region -Force | Out-Null
  $saprefix = get-random -Minimum 1000 -Maximum 10000000 
  $storageAccountName = 'aclxray' + $saprefix
  $storageAccount = New-AzStorageAccount -ResourceGroupName $RG -Name $storageAccountName -Location $region -type Standard_LRS
  New-AzStorageContainer -Name $containerName -Context $storageAccount.context  | Out-Null

}
#endregion



$destcontext = $storageAccount.context
$destSASToken = New-AzStorageContainerSASToken -Context $destcontext -ExpiryTime (get-date).AddHours(4).ToUniversalTime() -Name $containerName -Permission racwdl
$artifactSASTokenSecure = ConvertTo-SecureString -String $destSASToken -AsPlainText -Force 
$artifactLocation = "$($destcontext.BlobEndPoint)$($containerName)"

  

#generate SAS tokens to copy files from source to newly created storage account
Write-Verbose "Destination SAA $($destSAStoken)"


$ContosoDSConfigPath = "$($PSScriptRoot)\DSC\ContosoDCConfig.ps1"
$FabrikamDSConfigPath = "$($PSScriptRoot)\DSC\FabrikamDCConfig.ps1"
$EUDSConfigPath = "$($PSScriptRoot)\DSC\EUDCConfig.ps1"

$EUDSConfigURI = Publish-AzVMDscConfiguration -ResourceGroupName $RG -ConfigurationPath $EUDSConfigPath -StorageAccountName $storageAccountName -ContainerName $containerName -Force
$EUDSConfigFile = $EUDSConfigURI.Split("/")[-1]

$ContosoDSConfigURI = Publish-AzVMDscConfiguration -ResourceGroupName $RG -ConfigurationPath $ContosoDSConfigPath  -StorageAccountName $storageAccountName -ContainerName $containerName -Force
$ContosoDSConfigFile = $ContosoDSConfigURI.Split("/")[-1]

$FabrikamDSConfigURI = Publish-AzVMDscConfiguration -ResourceGroupName $RG -ConfigurationPath $FabrikamDSConfigPath  -StorageAccountName $storageAccountName -ContainerName $containerName -Force
$FabrikamDSConfigFile = $FabrikamDSConfigURI.Split("/")[-1]

  



Write-Verbose "Artifacts location $($ArtifactLocation)"
write-Verbose "Copying custom script artifacts"
Get-ChildItem .\CustomScripts | ForEach-Object {

  Set-AzStorageBlobContent -File $_.FullName -Blob $_.FullName.Substring((Get-Item $PSScriptRoot).FullName.Length + 1) -Context $destcontext -Container $containerName -Force| Out-Null

}
$templatefile = '.\azuredeploy.json'
$DeployParameters = @{
  "Name"                          =  "ACLXRALAB_$(get-date -UFormat %Y_%m_%d-%I-%M-%S%p)"
  "ResourceGroupName"             = $RG
  "TemplateFile"                  = $templatefile
  "virtualMachineSize"            = $vmsize
  "virtualNetworkName"            = $vnetname
  "shutdownTimeZone"              = $shutdownTimeZone
  "shutDownTime"                  = $shutDownTime
  "_artifactsLocation"            = $ArtifactLocation
  "_artifactsLocationSasToken"    = $artifactSASTokenSecure 
  "ContosoDCConfigArchiveFileName" = $ContosoDSConfigFile
  "FabrikamDCConfigArchiveFileName" = $FabrikamDSConfigFile
  "EUDSCConfigAcrhiveFileName" = $EUDSConfigFile
}
New-AzResourceGroupDeployment @DeployParameters
