
function write-log { 


    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        $message,
        [ValidateSet("ERROR", "INFO", "WARN", "SUCCESS")]
        $severity,
        $logfile

    )

    $WhatIfPreference = $false
    $timeStamp = get-date -UFormat %Y%m%d-%I:%M:%S%p
    switch ($severity) {

        "INFO" { [ConsoleColor]$messageColor = "Cyan" }
        "ERROR" { [ConsoleColor]$messageColor = "Red" }
        "WARN" { [ConsoleColor]$messageColor = "Yellow" }
        "SUCCESS" { [ConsoleColor]$messageColor = "Green" }
    
    }
    Write-Host "$($timeStamp) $($severity) $($message)" -ForegroundColor $messageColor
    if (!([string]::IsNullOrEmpty($logfile))) {
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
    "write-log:logfile"  = "$($env:ALLUSERSPROFILE)\$(($MyInvocation.MyCommand.Name).Split(".")[0]).log"
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
<##region configuring enabling WinRM with certbased auth and configuring firewall
$Cert = New-SelfSignedCertificate -CertstoreLocation Cert:\LocalMachine\My -DnsName $env:COMPUTERNAME
Enable-PSRemoting -SkipNetworkProfileCheck -Force
New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $Cert.Thumbprint -Force
New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -Name "Windows Remote Management (HTTPS-In)" -Profile Any -LocalPort 5986 -Protocol TCP
Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True -LogIgnored True
#endregion#>
#region set up domain data
Add-WindowsFeature RSAT-AD-PowerShell
$scriptRoot = split-path $myInvocation.MyCommand.Source -Parent
$domainData = get-addomain (Get-CimInstance Win32_ComputerSystem).Domain
$domainName = $domainData.NetbiosName
write-log "Connected to domain $($domainName)"
#endregion#>


#region set up grouops, file extensions and ACL collections
$businessGroups = Get-Content "$($scriptRoot)\groups.txt" 
$domainLocalGroups = get-adgroup -filter 'samaccountname -like "*-local-*"'
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
    $domainLocalGroups | Get-random -count (Get-random -Minimum 1 -Maximum 6) | forEach-Object {
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
            "IdenitylRefrence"  = "$($domainName)\$($domainLocalGroups.samaccountname | get-random)"
            "FileSystemRights"  = ($fileSystemRightsArray | Get-Random)
            "AccessControlType" = ($AccessControlTypeArray | Get-random)
            "File"              = $true

        }
        set-CustomACLs @customACLParams
    }
}
#endregion
#region Grating "" group permissions to start\stop Spooler service
$operatorsGroupSid = (Get-ADGroup -Identity 'Service Desk Operators').sid


$executable = "$($env:SystemRoot)\system32\sc.exe"
$parameters = "sdset Spooler D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;RPWPCR;;;$($operatorsGroupSid))S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"

$ps = new-object System.Diagnostics.Process
$ps.StartInfo.Filename = $executable
$ps.StartInfo.Arguments = $parameters
$ps.StartInfo.RedirectStandardOutput = $True
$ps.StartInfo.UseShellExecute = $false
$ps.start()
$ps.WaitForExit()
[string]$outputData = $ps.StandardOutput.ReadToEnd();

If (!($outputData -match "SUCCESS")) {
    Throw  "Adding permissions to spooler server failed with error`n$($outputData)"
}

#endregion

     


    