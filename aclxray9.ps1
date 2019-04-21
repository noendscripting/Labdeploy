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
[CmdletBinding()]
  
Param(
$vmsize = 'Standard_B2s',
$region = 'westus2',
$RG='ACLXRAYLAB',
$shutdownTimeZone='Pacific Standard Time',
$shutDownTime = '01:00',
[bool]$redeploy = $false,
$vnetname = 'ACLXRAYlabvnet',
$subnetname = 'subnet1'
)

Function get-StorageContext
{
  param(
    $storageName,
    $strageRG
  )
  $storagekey = (get-azureRMstorageaccountkey -resourcegroupname $strageRG -StorageAccountName $storageName).value[1]
  Return New-AzureStorageContext -StorageAccountName $storageName -StorageAccountKey $storagekey
}

if (!(get-module AzureRM))
{
  Enable-AzureRmAlias
}



$currentContext = Get-AzureRmContext -ErrorAction SilentlyContinue

if ([string]::IsNullOrEmpty($currentContext))
{
  login-azurermaccount

}

#verifying deployimnet subscription
$title = "ACLXRAY Lab deployment"
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
    Get-AzureRMSubscription | Select-Object name | Out-Host
    [string]$subscription = Read-Host "Please type subscription name in the box below.`nPress enter if you want to exit the srcipt"
    if ([string]::IsNullOrEmpty($subscription))
    {
     Write-Host "Operation canceled.Ending script" 
     Exit
    }
    else {
      Select-AzureRMSubscription -Subscription $subscription
    }
  }
}

#

#-----------------------------------------------
#create resourcegroup
if(!($redeploy))
{
  #Create Resource Group
  New-AzureRmResourceGroup -Name $RG -Location $region
  #Create storage account for disks in a lab
  $saprefix=get-random -Minimum 1000 -Maximum 10000000 
  $saname = 'aclxray'+$saprefix
  New-AzureRMStorageAccount -ResourceGroupName $RG -Name $saname -Location $region -type Standard_LRS | Out-Null
  $destcontext = get-StorageContext -storageName $saname -strageRG $RG
  $destcontainer = New-AzureStorageContainer -Name 'images' -Context $destcontext
  New-AzureStorageContainer -Name 'vhds' -Context $destcontext | Out-Null

  #setup vars to copy files from source to newly created storage account
  $sourcesaname = 'aclxray586844'
  $sourcekey= 'UvzfWkCDNS9dip/NdUJwEZM9wy+Jq7spMW/R91327NV3LpMd2J1p1z1N0iFcwgC0HyxVPf7qCQN4QH0/0AChpA=='
  $sourcecontext = New-AzureStorageContext -StorageAccountName $sourcesaname -StorageAccountKey $sourcekey
  $sourcecontainer = Get-AzureStoragecontainer -Context $sourcecontext | Where {$_.Name -eq 'images'}
  $blobs = get-azurestorageblob -container $sourcecontainer.Name -Context $sourcecontext | Where-Object {$_.snapshottime -eq $null} 

  #file copy
  foreach ($b in $blobs)
  {
    Start-AzureStorageBlobCopy -SrcContainer $sourcecontainer.name -DestContainer $destcontainer.name -Context $sourcecontext -DestContext $destcontext -SrcBlob $b.Name 
  }
  write-host "Copy could take some time please be patient. Generally 1-3 hours is normal, but there is no SLA in Azure for storage account copies" -ForegroundColor yellow
  #below status checks are functioning to hold script until all blobs are completed copying
  $_copytime = get-date
  $Blobs | ForEach-Object {
    while ((get-azurestorageblob $_.name -context $destcontext -Container $destcontainer.name | get-azurestorageblobcopystate).Status -eq "pending"){
        $_results = get-azurestorageblob $blobs[1].name -context $destcontext -Container $destcontainer.name | get-azurestorageblobcopystate
        Write-Progress -Id 1 -Activity "Copying Blobs" -Status "Progress: $((($_results).bytescopied/1Gb).ToString("###.##"))GB of $((($_results).TotalBytes/1GB).ToString("###.##"))GB - Total Time Passed: $((new-TimeSpan($_copytime) $(Get-Date)).TotalMinutes) minutes" -PercentComplete ($(($_results).bytescopied)/$(($_results).TotalBytes)*100)
        start-sleep -Seconds 60
    }
  }
  Write-Progress -Id 1 -Completed -Activity "Copying Blobs"
  write-host "Total copy time $((new-TimeSpan($_copytime) $(Get-Date)).TotalMinutes) minutes" -foregroundcolor yellow
}
else
{
  #getting information about existing lab infrastructure
  $saname = (Get-AzureRmStorageAccount -resourcegroupname $RG | where-object {$_.StorageAccountName -like "aclxray*"}).StorageAccountName
  $destcontext = get-StorageContext -storageName $saname -strageRG $RG
}







              
#set vars for path of VHD file for each vm to be deployed
$contosoVHD = $destcontext.BlobEndPoint + 'images/contosodc120170331122936.vhd'
$eudc1vhd = $destcontext.BlobEndPoint + 'images/eucontosodc120170417083825.vhd'
$fabdcvhd = $destcontext.BlobEndPoint + 'images/fabrikamdc120170331123706.vhd'
$exchvhd =  $destcontext.BlobEndPoint + 'images/contosoex120170331131217.vhd'
$contosofsvhd = $destcontext.BlobEndPoint + 'images/contosofs120170331123927.vhd'
$fabfsvhd = $destcontext.BlobEndPoint + 'images/fabrikamFS120170331130906.vhd'
$eufsvhd = $destcontext.BlobEndPoint + 'images/EUFS120170331131044.vhd'
#set arrays for disk and server name variables
[array]$disks = @($contosoVHD,$eudc1vhd,$fabdcvhd,$exchvhd,$contosofsvhd,$fabfsvhd,$eufsvhd)
[array]$names = @("contosodc1", "eucontosodc1","fabrikamdc1","contosoex1","contosofs","fabrikamfs","eufs" )

$templatefile= './lab-complete.json'

#Creating deployment parameters object
$DeployParameters = @{
"Name" = 'ACLXRALAB'
"ResourceGroupName"= $RG
"TemplateFile"=$templatefile
"ostype" = 'Windows'
"vmName" = $names
"osdiskvhduri" = $disks
"vmsize" = $vmsize
"VNETName" = $vnetname
"subnetname" = $subnetname
"shutdownTimeZone" = $shutdownTimeZone
"shutDownTime" = $shutDownTime
}

#deployment of contosodc1 waiting for this one to deploy first since it is the forest root
New-AzureRmResourceGroupDeployment @DeployParameters
<#-Name 'ACLXRALAB' -ResourceGroupName $RG -TemplateFile $templatefile `
-ostype 'Windows' -vmName $names -osdiskvhduri $disks -vmsize $vmsize -VNETName $vnetname `
-subnetname $subnetname -shutdownTimeZone $shutdownTimeZone -shutDownTime $shutDownTime #>

#stopping VMs 

Write-Host "Shutting down VMs to save costs" -ForegroundColor Yellow

Get-AzureRmVM -ResourceGroupName $RG | Stop-AzureRmVM -force

Write-host "Lab deployment is now complete. The VMs are stopped. Please run aclxray_start_lab.ps1 to start them" -ForegroundColor Cyan