
function write-log { 


    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        $message,
        [ValidateSet("ERROR", "INFO", "WARN")]
        $severity,
        $logfile

    )

    $WhatIfPreference = $false
    $timeStamp = get-date -UFormat %Y%m%d-%I:%M:%S%p
    switch ($severity) {

        "INFO" { $messageColor = "Green" }
        "ERROR" { $messageColor = "Red" }
        "WARN" { $messageColor = "Yellow" }
    
    }
    Write-Host "$($timeStamp) $($severity) $($message)" -ForegroundColor $messageColor
    if ($logfile.length -ge 0) {
        write-output "$($timeStamp) $($severity) $($message)" | Out-File -FilePath $logfile -Encoding ascii -Append
    }
}



function set-CustomACLs {
    param(
        [string]$TargetPath,
        [string]$IdenitylRefrence,
        [string]$FileSystemRights,
        [string]$InheritanceFlags,
        [string]$PropagationFlags,
        [string]$AccessControlType,
        [bool]$file
    )

    $acl = Get-Acl $TargetPath

    if ($file) {
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($IdenitylRefrence, $FileSystemRights, $AccessControlType)
    }
    else {
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($IdenitylRefrence, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
    }
        
    $acl.SetAccessRule($accessRule)
    $acl | Set-Acl $TargetPath
    write-log "Granted $($FileSystemRights) Permisison to Group $($accessRule.IdentityReference) to $($TargetPath)"

}



#region logging parameters
$PSDefaultParameterValues = @{

    "write-log:severity" = "INFO";
    "write-log:logfile"  = "$($env:ALLUSERSPROFILE)\$($MyInvocation.MyCommand.Name).log"
}
    
    
if ($log.Length -ne 0) {
    if (Test-Path (split-path $log -parent)) {
        $PSDefaultParameterValues["write-log:logfile"] = $log
        write-log "Setting location of log file to $($log)"
    
    }
    else {
        write-log "Custom log is not found setting log to $($env:ALLUSERSPROFILE)\$($MyInvocation.MyCommand.Name).log"
    }
    
}
trap { write-log -message "$($_.Message)`n$($_.ScriptStackTrace)`n$($_.Exception)" -severity "ERROR"; break; }
#endregion 
#region set up domain data
Add-WindowsFeature RSAT-AD-PowerShell

$domainData = get-addomain (Get-CimInstance Win32_ComputerSystem).Domain
$domainDN = $domainData.distinguishedname
$domainName = $domainData.NetbiosName
write-log "Connect to domain $($domainName)"
#endregion
#New-Service -Name "Generic Service" -BinaryPathName "C:\WINDOWS\System32\svchost.exe -k netsvcs"

#region set up grouops, file extensions and ACL collections
$businessGroups = Get-Content "$($PSScriptRoot)\groups.txt" 
$genericGroups = get-adgroup -filter 'samaccountname -like "*-general-*"'
$MultimediaExtensions = ".avi", ".midi", ".mov", ".mp3", ".mp4", ".mpeg", ".mpeg2", ".mpeg3", ".mpg", ".ogg", ".ram", ".rm", ".wma", ".wmv"
$OfficeExtensions = ".pptx", ".docx", ".doc", ".xls", ".docx", ".doc", ".pdf", ".ppt", ".pptx", ".dot"
$AllExtensions = $MultimediaExtensions + $OfficeExtensions
$inheritanceFlagsArray = @(0, 1, 2)
$propagationFlagsArray = @(0, 1, 2)
$AccessControlTypeArray = @(0, 1)
$fileSystemRightsArray = @("FullControl", "Modify", "Write", "Read", "ListDirectory", "Traverse")
#endregion
#region create foleders, shares, files and ACLs
forEach ($buGroup in $businessGroups) {
    $targetPath = "C:\File_Share\$($buGroup)\"
    New-Item $targetPath -type directory
    write-log "Created business directory $($targetPath)"
    New-SMBShare -Name $buGroup -Path $targetPath -FullAccess "$($domainName)\$($bugroup)"
    write-log "Created share $($buGroup) using path $($targetPath)"
    #selecting ramdom genral groiup and assigning to the newly created folder with random permissions 
    $genericGroups | Get-random -count (Get-random -Minimum 1 -Maximum 6) | forEach-Object {
        $customACLParams = @{
            "TargetPath"        = $targetPath
            "IdenitylRefrence"  = "$($domainName)\$($psitem.samaccountname)"
            "FileSystemRights"  = ($fileSystemRightsArray | Get-Random)
            "InheritanceFlags"  = ($inheritanceFlagsArray | Get-random)
            "PropagationFlags"  = ($propagationFlagsArray | Get-random)
            "AccessControlType" = ($AccessControlTypeArray | Get-random)
            "File"              = $false

        }

        set-CustomACLs @customACLParams
    }
    $totalfiles = get-random -Minimum 53 -Maximum 207
    for ($i = 0; $i -le $totalfiles; $i++) {
        $fileName = ([System.IO.Path]::GetRandomFileName()).Split('.')[0]
        $extension = $AllExtensions | Get-Random
        New-Item "$($targetPath)$($fileName)$($extension)" -type file -Force | Out-Null 
        write-log "Created ramdom file $($targetPath)$($fileName)$($extension)"
        Clear-Variable fileName
        Clear-Variable extension 

    }
    #selecting random files and assigning random permssions to a random generic group
    Get-ChildItem $targetPath | Get-Random -Count 3 | ForEach-Object {

        $customACLParams = @{
            "TargetPath"        = $psitem.FullName
            "IdenitylRefrence"  = "$($domainName)\$($genericGroups.samaccountname | get-random)"
            "FileSystemRights"  = ($fileSystemRightsArray | Get-Random)
            "AccessControlType" = ($AccessControlTypeArray | Get-random)
            "File"              = $true

        }
        set-CustomACLs @customACLParams
    }
}
     
     


    