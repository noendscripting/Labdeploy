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

.
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

function RecoverVM {
    [CmdletBinding()]
    param (
        $VmData,
        $rg
    )
    $ErrorActionPreference = 'Stop'
    $diskGUID = New-Guid
    $osDiskName = "$($VmData.Name)_OSDisk_$($diskGUID.ToString('N'))"
    $vmSize = $vmData.HardwareProfile.VmSize
    $vmName = $VmData.Name
    $snapshotname = "Snapshot_$($VmData.Name)_OSDisk"
    
    Write-Host "Setting up recovery properties" -ForegroundColor Green
    $snapshot = Get-AzSnapshot -ResourceGroupName $rg -SnapshotName $snapshotName -ErrorAction Continue
    IF ([string]::IsNullOrEmpty($snapshot.OsType)) {
        Write-Host "Snapshot for VM $($VmData.Name) is not found. Exiting Loop" -ForegroundColor Red
        break 
    }
    Write-Host "Snapshot for VM $($VmData.Name) found. Starting recovery configuration"
    $diskConfig = New-AzDiskConfig -Location $snapshot.Location -SourceResourceId $snapshot.Id -CreateOption Copy
    $disk = New-AzDisk -Disk $diskConfig -ResourceGroupName $rg -DiskName $osDiskName 
    $newVmConfig = New-AzVMConfig -VMSize $vmSize -VMName $vmName
    $newVmConfig = Set-AzVMOSDisk -VM $newVmConfig -ManagedDiskId $disk.Id -CreateOption Attach -Windows
    $newVmConfig = Add-AzVMNetworkInterface -VM $newVmConfig  -Id $VmData.NetworkProfile.NetworkInterfaces[0].id
    Write-Host "Deleting original VM" -ForegroundColor Cyan
    Remove-AzVM  -Id $VmData.id -Force -Verbose
    Write-Host "Creating new VM" -ForegroundColor Cyan
    New-AzVM -VM $newVmConfig  -ResourceGroupName $rg -Location $snapshot.Location




    
}

If ([string]::IsNullOrEmpty($VMName) -and !($all)) {
    Write-Host "No VM names specified in the reqeust.`nPlease either use -All '$true' switch or pass VM name via -VMname switch" -ForegroundColor Red
    exit
}

#region Verifying current Azure connection state
Write-Host "Verifing current access to Azure" -ForegroundColor Cyan
$currentContext = Get-AzContext 
if ([string]::IsNullOrEmpty($currentContext)) {
    Login-AzAccount

}
Write-Host "Access verified proceeding to create snapshots" -ForegroundColor Cyan
#endregion

#saving function as a string script block for use in ForEach-Object -Parallel
$funcDef = $function:RecoverVM.ToString()
if ($all) {
    get-azvm -ResourceGroupName $resourceGroupName | ForEach-Object -Parallel {
        Write-Host "Starting roll back of VM $($PsItem) from snapshot" -ForegroundColor Cyan
        $Function:RecoverVM = $using:funcDef
        recoverVM -VmData $PsItem -rg $using:resourceGroupName
    }
}
else {
    $VMName | ForEach-Object -Parallel {
        Write-Host "Starting roll back of VM $($PsItem) from snapshot" -ForegroundColor Cyan
    
        $vm = get-azvm -ResourceGroupName $using:resourceGroupName -Name $PSItem -ErrorVariable errordata -ErrorAction SilentlyContinue
        if (!([string]::IsNullOrEmpty($errorData))) {
            Write-Host "VM $($PSItem) not found in a Resource Group $($using:resourceGroupName)" -ForegroundColor Red
            Continue 
        }
        Write-Host "VM $($PSItem) found in a Resource Group $($using:resourceGroupName)" -ForegroundColor Green
        $Function:RecoverVM = $using:funcDef
        recoverVM -VmData $vm -rg $using:resourceGroupName
    }
}