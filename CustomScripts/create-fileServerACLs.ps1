
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
    Write-Host "$($timeStamp)`t[$($severity)]`t$($message)" -ForegroundColor $messageColor
    if (!([string]::IsNullOrEmpty($logfile))) {
        write-output "$($timeStamp)`t[$($severity)]`t$($message)" | Out-File -FilePath $logfile -Encoding ascii -Append
    }
}

function set-CustomACLs {
    param(
        [string]$TargetPath,
        [string]$IdentitylRefrence,
        [string]$FileSystemRights,
        [string]$InheritanceFlags,
        [string]$PropagationFlags,
        [string]$AccessControlType,
        [bool]$file
    )

    $acl = Get-Acl $TargetPath

    if ($file) {
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($IdentitylRefrence, $FileSystemRights, $AccessControlType)
    }
    else {
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($IdentitylRefrence, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
    }
        
    $acl.SetAccessRule($accessRule)
    $acl | Set-Acl $TargetPath
    write-log "Granted $($FileSystemRights), Permisison to Principal $($accessRule.IdentityReference) to $($TargetPath) InheritanceFlags $($InheritanceFlags) PropagationFlags $($PropagationFlags) AccessControlType $($AccessControlType) " -severity SUCCESS

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
#region Set .Net to use TLS settings from OS
write-log "Setting TLS negotiation porperties for .Net 4.x"
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null
write-log "Setting TLS negotiation porperties for .Net 2.x"
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v2.0.50727' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v2.0.50727' -name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null
#endregion
#region set up domain data
Add-WindowsFeature RSAT-AD-PowerShell
$scriptRoot = split-path $myInvocation.MyCommand.Source -Parent
$domainData = get-addomain (Get-CimInstance Win32_ComputerSystem).Domain
$domainName = $domainData.NetbiosName
$domainDN = $domainData.distinguishedname
$groupsOU = "OU=Security Groups,OU=Groups,$($domainDN)"
write-log "Connected to domain $($domainName)" -severity SUCCESS
#endregion#>

#region set windows firewall settings for logging
Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True -LogIgnored True
#endregion

#region create folders, shares, files
$filesystemData = import-csv "$($scriptRoot)\$($domainName)-file-directory.csv"
forEach ($target in $filesystemData) {
    
    New-Item $target.path -type $target.type | Out-Null
    write-log "Created directory $($target.Path)" -severity SUCCESS
    if ($target.type -eq 'directory') {
        New-SMBShare -Name $target.Path.Split("\")[2]  -Path $target.path -FullAccess "$($domainName)\$($target.Path.Split("\")[2])" | Out-Null
        write-log "Created share $($target.Path.Split("\")[2]) using path $($target.Path)" -severity SUCCESS
    }
}

#endregion
#region Create permisisons on directories and files

write-log "Setting permissions on files and directories"
$aclData = import-csv "$($scriptRoot)\$($domainName)-file-permissions.csv"

foreach ($aclEntry in $aclData) {

    $customACLParams = @{
        "TargetPath"        = $aclEntry.targetPath
        "IdentitylRefrence"  = "$($domainName)\$($aclEntry.IdentitylRefrence)"
        "FileSystemRights"  = $aclEntry.FileSystemRights
        "InheritanceFlags"  = $aclEntry.InheritanceFlags
        "PropagationFlags"  = $aclEntry.PropagationFlags
        "AccessControlType" = $aclEntry.AccessControlType
        "File"              = [System.Convert]::ToBoolean($aclEntry.File)

    }
    set-CustomACLs @customACLParams

}

    
#region Granting Service Desk Operators group permissions to start\stop Spooler service
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
else {
    write-log "Granted permissions to start\stop spooler to Service Desk Operators group" -severity SUCCESS
}

#endregion

     


    