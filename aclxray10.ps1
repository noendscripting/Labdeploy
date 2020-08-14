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

  Script deploys a test lab for AclXray including 7 VMs. Use your internal azure subscription to deploy this. 

.DESCRIPTION
  
    This will deploy a new resource group called ACLXRAYLAB with a new VNET called ACLXRAYlabvnet on 10.6.0.0/24. It will then create a new storage account, copy blob VHDs to that storage account
    then use ARM template to deploy the lab VMs on basic_a1 size to the new vnet/rg. The VM names are: contosodc1, contosoex1, contosofs1, fabrikamdc1, fabrikamfs1, eucontosodc1, eufs1
    all resources are deployed to WESTUS2, if you change this in the script, copy time will be very slow

.PARAMETER <Parameter_Name>
    vmsize for the vm sizes for all vms (standard_A2_V2 is default)
    region is for deployment region (westus2 is default, source images are stored in westus2 as well so other regions will take longer to deploy)
    rg is for the resourcegroup name. Default is aclxraylab
    shutdownTimeZone is to to set time zone for shutdown schedler. Default Pacific Time Zone
    redeploy true\false is to enable option redeploy lab if you preserved original VHDs and do not want to copy them again. Default fail
    vnetname Name of the VNET for the lab default 'ACLXRAYlabvnet'
    subnetname is named for the lab subnet. default 'subnet1'



.INPUTS
   The script will ask for credentials. These are the credentials for your azure subscription, not the VMs. VM creds are already set.

.NOTES
  Version:        9.0
  Author:         Mike Resnick Microsoft
  Creation Date: 4/4/2018

 Added verification if user is already logged to Azure.
 Added confirmation user wants to deploy 7 VMs to existing subscription
 Added option to select another subscription or exit
 Added code in the copy progress bar to show GBs copied.
 Added verification to enable AzureRM aliase for Az module
 Moved all deployment functions into template
 Changed default size of the VMs to Standard_B2s to save money
 Added code to dispose of progress bar
 Added redeploy option if original disks were already copied
 Replaced variable with Out-Null where command created an and output was not needed
 Added a custom script for Windows Server 2012 R2 to run Windows Update and install if missing
Added shutdown schedule  to VMs

#This is for internal Microsoft use only

#>
#Requires -Modules @{ ModuleName="Az"; ModuleVersion="4.5.0" }
[CmdletBinding()]
  
Param(
  #$vmsize = 'Standard_B2s',
  $vmsize = 'Standard_B4ms',
  $region = 'westus2',
  $RG = 'ACLXRAYLAB',
  $shutdownTimeZone = 'Pacific Standard Time',
  $shutDownTime = '01:00',
  [bool]$redeploy = $false,
  $vnetname = 'ACLXRAYlabvnet',
  $containerName = "storageartifacts"

)





$currentContext = Get-AzContext 
if ([string]::IsNullOrEmpty($currentContext)) {
  Login-AzAccount

}

#verifying deployimnet subscription
<#$title = "ACLXRAY Lab deployment"
$message = "You are about to deploy 7 VMs into subscription ""$($currentContext.Subscription.Name)""`nDo you want to proceed?"
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
}#>

#

#-----------------------------------------------



#Create Resource Group, Storage Account and Container

Get-AzResourceGroup -Name $RG -ErrorAction SilentlyContinue -ErrorVariable errorData | Out-Null
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





$destcontext = $storageAccount.context
$destSASToken = New-AzStorageContainerSASToken -Context $destcontext -ExpiryTime (get-date).AddHours(4).ToUniversalTime() -Name $containerName -Permission racwdl
$artifactSASTokenSecure = ConvertTo-SecureString -String $destSASToken -AsPlainText -Force 
$artifactLocation = "$($destcontext.BlobEndPoint)$($containerName)"

  

#generate SAS tokens to copy files from source to newly created storage account
Write-Verbose "Destination SAA $($destSAStoken)"


#$ContosoDSConfigPath = "$($PSScriptRoot)\DSC\ContosoDCConfig.ps1"
$ForestDSConfigPath = "$($PSScriptRoot)\DSC\ForestDCConfig.ps1"
$EUDSConfigPath = "$($PSScriptRoot)\DSC\EUDCConfig.ps1"

$EUDSConfigURI = Publish-AzVMDscConfiguration -ResourceGroupName $RG -ConfigurationPath $EUDSConfigPath -StorageAccountName $storageAccountName -ContainerName $containerName -Force
$EUDSConfigFile = $EUDSConfigURI.Split("/")[-1]

#$ContosoDSConfigURI = Publish-AzVMDscConfiguration -ResourceGroupName $RG -ConfigurationPath $ContosoDSConfigPath  -StorageAccountName $storageAccountName -ContainerName $containerName -Force
#$ContosoDSConfigFile = $ContosoDSConfigURI.Split("/")[-1]

$ForestDSConfigURI = Publish-AzVMDscConfiguration -ResourceGroupName $RG -ConfigurationPath $ForestDSConfigPath  -StorageAccountName $storageAccountName -ContainerName $containerName -Force
$ForestDSConfigFile = $ForestDSConfigURI.Split("/")[-1]

  



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
  "ContosoDCConfigArchiveFileName" = $ForestDSConfigFile
  "FabrikamDCConfigArchiveFileName" = $ForestDSConfigFile
  "EUDSCConfigAcrhiveFileName" = $EUDSConfigFile
}
New-AzResourceGroupDeployment @DeployParameters
