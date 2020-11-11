<#
    This code is Copyright (c) 2020 Microsoft Corporation.

    All rights reserved.
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
    INCLUDING BUT NOT LIMITED To THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.'

    IN NO EVENT SHALL MICROSOFT AND/OR ITS RESPECTIVE SUPPLIERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR 
    CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
    WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
    WITH THE USE OR PERFORMANCE OF THIS CODE OR INFORMATION.

.SYNOPSIS

  Script creates OD disk snapshots of VMs for the ACLXRAY Lab. 

.DESCRIPTION
  
  This create will either create snapshot for all VMs in the resource group wher AclXray lab is deployed.

.PARAMETER VmName
    Ths is a string array that allows passing of a single or multiple VMs
.PARAMETER All
    This is boolean parameter, when  set to $true forces script to create snapshot of all VMs in the the resource group. Default is $false
.PARAMETER ResourceGroupName
    Name of the resource group where VM are created and where snapshots will be stored.
.EXAMPLE
    Creating snapshots for all VMs in resoucre group, using default ResourceGroup value
    .\Create-ACLxrayVmSnapShots.ps1 -All $true
.EXAMPLE
    Creating snapshot for a single VM using default ResourceGroup value
    .\Create-ACLxrayVmSnapShots.ps1 -VMName <your VM name here>
.EXAMPLE
    Creating snapshot of multiple VMs in a non default resource group
    .\Create-ACLxrayVmSnapShots.ps1 -VMName "VM1","VM2" -ResourceGroupName <your resource group name here>



.INPUTS
   The script may ask for credentials if you are not already logged on to Azure. These are the credentials for your azure subscription



#This is for internal Microsoft use only

#>

#Requires -Version 7.0
#Requires -Modules Az
[CmdletBinding()]

param (
    [string[]]$VMName,
    [bool]$All = $false,
    [string]$resourceGroupName = 'ACLXRAYLAB'
)

function NewOSDiskSnapshot {
    [CmdletBinding()]
    param (
        $name,
        $VmData,
        $loc,
        $rg
    )
    $snapshot = New-AzSnapshotConfig -SourceUri $VmData.StorageProfile.OsDisk.ManagedDisk.Id -Location $loc -CreateOption copy -SkuName "Standard_LRS" -Verbose
    $snapshotResult = New-AzSnapshot -Snapshot $snapshot -SnapshotName $name -ResourceGroupName $rg -Verbose

    if ($snapshotResult.ProvisioningState -eq "Succeeded") {
        Write-Host "Snapshot for VM $($vmData.Name) created successfully. Snapshop name $($snapshotname)" -ForegroundColor Green
    }
    else {
        Write-Host "Snapshot for VM $($vmData.Name) failed" -ForegroundColor Red
    }
    
}

If ([string]::IsNullOrEmpty($VMName) -and !($all))
{
    Write-Host "No VM names specified in the reqeust.`nPlease either use -All '$true' switch or pass VM name via -VMname switch" -ForegroundColor Red
    exit
}

#region Verifying current Azure connection state
Write-Host "Verifing current access to Azure" -ForegroundColor Green
$currentContext = Get-AzContext 
if ([string]::IsNullOrEmpty($currentContext)) {
  Login-AzAccount

}
Write-Host "Access verified proceeding to create snapshots"
#endregion


$location = (Get-AzResourceGroup -Name $resourceGroupName).Location
#saving function as a string script block for use in ForEach-Object -Parallel
$funcDef = $function:NewOSDiskSnapshot.ToString()
if ($all) {
    get-azvm -ResourceGroupName $resourceGroupName | ForEach-Object -Parallel {
        Write-Host "Starting Snapshot of VM $($PsItem.Name)" -ForegroundColor Green
        $snapshotname = "Snapshot_$($PsItem.Name)_OSDisk"
        #Declaring function inside ForEach-Obejct -Parallel loop from the variable with the saved script-block
        $Function:NewOSDiskSnapshot = $using:funcDef
        NewOSDiskSnapshot -name $snapshotname -VmData $PsItem -loc $using:location -rg $using:resourceGroupName
    }
}
else {
    $VMName | ForEach-Object -Parallel {
        Write-Host "Starting Snapshot of VM $($PsItem)" -ForegroundColor Green
        $vm = get-azvm -ResourceGroupName $using:resourceGroupName -Name $PSItem
        $snapshotname = "Snapshot_$($PsItem)_OSDisk"
        #Declaring function inside ForEach-Obejct -Parallel loop from the variable with the saved script-block
        $Function:NewOSDiskSnapshot = $using:funcDef
        NewOSDiskSnapshot -name $snapshotname -VmData $vm -loc $using:location -rg $using:resourceGroupName       
    }
}