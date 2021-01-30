
[CmdletBinding()]

param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]$remoteUser,
    [Parameter(Position = 1, Mandatory = $true)]
    [string]$remotePassword
)
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
Function add-PrivelegedUsers {
    param (
        [string]$ou,
        [string]$prefix,
        [int16]$Tier
    )
    get-adgroupmember "Strategic Information Systems" | Get-Random -Count 5 | ForEach-Object {
        Get-ADUser -Identity $PSItem.DistinguishedName | ForEach-Object {
            $samAccountName = "$($prefix)$($_.samaccountname)"
            New-ADUser -Name $PSItem.name -displayname $PSItem.name -userprincipalname "$($samAccountName)@$($upnSuffix)" -City $PSItem.city -Company "Contoso" -Country US -EmailAddress $PSItem.EmailAddress -GivenName $PSItem.GivenName -MobilePhone $PSItem.mobile -OfficePhone $PSItem.OfficePhone -PostalCode $PSItem.PostalCode -description "Server Admin Account" -SamAccountName  $samAccountName -State $_.state -StreetAddress $_.StreetAddress -Surname $_.Surname -path $ou -AccountPassword (ConvertTo-SecureString -AsPlainText "!Th1sn33dsto b3ash@rdas1tc@n" -Force) -Enabled $true
            write-log "Added priveleged Tier $($Tier) account $($PSItem.name)" -severity SUCCESS
        }
    }

}
Function Add-UsersToPrivelgedGroups {
    param (
        [string]$ou,
        [string[]]$groups

    )

    forEach ($group in $groups) {
        get-aduser -filter * -searchbase $ou | Get-Random -Count 3 | ForEach-Object {
            get-adgroup $group | Add-ADGroupMember -members $PSItem
            write-log "Added $($PSItem.name) to $($group)" -severity SUCCESS
        }
    }
}
function Set-OuDelegation {
    param(
        [string]$group,
        [string]$jsRightsObject,
        [string]$targetOU
    ) 
    
    $importedPermissions = $jsRightsObject | convertFrom-json
    $groupProperties = Get-ADGroup $group
    ForEach ($importedPermission in $importedPermissions) {
        $rightsObject = New-Object System.DirectoryServices.ActiveDirectoryAccessRule([System.Security.Principal.SecurityIdentifier]$groupProperties.SID, $importedPermission.ActiveDirectoryRights, $importedPermission.AccessControlType, [GUID]$importedPermission.ObjectType, $importedPermission.InheritanceType, [GUID]$importedPermission.InheritedObjectType)
        $ACL = Get-Acl -path "AD:\$($targetOU)"      
        $ACL.AddAccessRule($rightsObject)
        Set-Acl -Path "AD:\$($targetOU)" -AclObject $ACL
        write-log "Added group $($groupProperties.Name) permissions $($importedPermission.ActiveDirectoryRights) to $($targetOU)" -severity SUCCESS
        Clear-Variable rightsObject, ACL
    
    }

}
function set-CustomACLs {
    param(
        [string]$TargetPath,
        [string]$IdenitylRefrence,
        [string]$FileSystemRights,
        [string]$InheritanceFlags,
        [string]$PropagationFlags,
        [string]$AccessControlType
    )

    $acl = Get-Acl $TargetPath
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($IdenitylRefrence, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
    $acl.SetAccessRule($accessRule)
    $acl | Set-Acl $TargetPath
    write-log "Granted $($FileSystemRights) Permisison to Group $($accessRule.IdentityReference) to $($TargetPath)" -severity SUCCESS

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
        write-log "Custom log is not found setting log to $($env:ALLUSERSPROFILE)\$(($MyInvocation.MyCommand.Name).Split(".")[0]).log"
    }
    
}
trap { write-log -message "$($_.Message)`n$($_.ScriptStackTrace)`n$($_.Exception)" -severity "ERROR"; break; }
#endregion
#region Set .Net to use TLS settings from OS
write-log "Setting TLS negotiation porperties for .Net 4.x"
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null
write-log "Setting TLS negotiation porperties for .Net 2.x"
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v2.0.50727' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null
#endregion
#region setting local domain variables
$scriptRoot = split-path $myInvocation.MyCommand.Source -Parent
$domainData = Get-ADDomain
$domainDN = $domainData.distinguishedname
$domainName = $domainData.NetbiosName
$domainFQDN = $domainData.DNSRoot
#endregion
#region creating json with OU delegation details
$jsonDelegationDetails = @"
[
  {
    "ActiveDirectoryRights": "GenericAll",
    "InheritanceType": "Descendents",
    "ObjectType": "00000000-0000-0000-0000-000000000000",
    "InheritedObjectType": "bf967aba-0de6-11d0-a285-00aa003049e2",
    "ObjectFlags": "InheritedObjectAceTypePresent",
    "AccessControlType": "Allow",
    "IsInherited": "False",
    "InheritanceFlags": "ContainerInherit",
    "PropagationFlags": "InheritOnly"
  },
  {
    "ActiveDirectoryRights": "ReadProperty, WriteProperty",
    "InheritanceType": "All",
    "ObjectType": "f30e3bbf-9ff0-11d1-b603-0000f80367c1",
    "InheritedObjectType": "00000000-0000-0000-0000-000000000000",
    "ObjectFlags": "ObjectAceTypePresent",
    "AccessControlType": "Allow",
    "IsInherited": "False",
    "InheritanceFlags": "ContainerInherit",
    "PropagationFlags": "None"
  },
  {
    "ActiveDirectoryRights": "CreateChild, DeleteChild",
    "InheritanceType": "All",
    "ObjectType": "bf967a9c-0de6-11d0-a285-00aa003049e2",
    "InheritedObjectType": "00000000-0000-0000-0000-000000000000",
    "ObjectFlags": "ObjectAceTypePresent",
    "AccessControlType": "Allow",
    "IsInherited": "False",
    "InheritanceFlags": "ContainerInherit",
    "PropagationFlags": "None"
  }
]
"@
#endregion
#region adding users
$usersOU = "OU=Enabled Users,OU=User Accounts, $($domainDN)"
write-log "Adding user to $($domainName)"
foreach ($user in (import-csv "$scriptRoot\$($domainName)-users.csv")) {
    $name = $user.first + " " + $user.last

    $newUserObject = @{

        Name              = $name
        City              = $user.city
        Company           = $user.Company
        Department        = $user.Department
        Country           = $user.Country
        EmailAddress      = $user.email
        GivenName         = $user.first
        MobilePhone       = $user.phone
        OfficePhone       = $user.phone
        PostalCode        = $user.zip
        SamAccountName    = $user.samaccountname
        State             = $user.state
        StreetAddress     = $user.Street
        Surname           = $user.last
        UserPrincipalName = $user.email
        path              = $usersOU
        AccountPassword   = (ConvertTo-SecureString -AsPlainText "!Th1sn33dsto b3ash@rdas1tc@n" -Force)
        Enabled           = $true
        
    }
    New-ADUser @newUserObject
    write-log "Added user $($name)" -severity SUCCESS
    Clear-Variable name
}
#endregion
#region creating groups
write-log "Creating groups"
$groupsOU = "OU=Security Groups,OU=Groups,$($domainDN)"
$groupData = import-csv "$scriptRoot\$($domainName)-groups.csv"


foreach ($group in $groupData) {
    New-ADGroup $group.GroupName -SamAccountName $group.GroupName -DisplayName $group.GroupName -GroupScope $group.Type -GroupCategory Security -Path $groupsOU
    write-log "Created $($group.Type) group $($group.GroupName)" -severity SUCCESS
}
write-log "Getting list of created groups"
$groups = get-adgroup -filter * -SearchBase $groupsOU
write-log "Getting list of department groups"
$departmentGroups = $groups | Where-Object { $_.SamAccountName -notlike 'grp-*' }
#endregion
#region Adding OU delegations
write-log "Setting up delegations in OUs"
Set-OuDelegation -group "Service Desk Operators" -jsRightsObject $jsonDelegationDetails -targetOU "OU=Enabled Users,OU=User Accounts, $($domainDN)" 
#endregion
#region Adding members to groups
write-log "Assigning Group Membership"
$memberData = Import-Csv "$scriptRoot\$($domainName)-groups-members.csv" | group -AsHashTable -Property Group
forEach ($groupName in $memberData.Keys) {
    $memberArray = $memberData.$groupName.Member
    Add-ADGroupMember -Identity $groupName -Members $memberArray
    write-log "Added $($memberArray) to group $($groupName)" -severity SUCCESS 
}
#endregion
#region create manager\report entries for each department
write-log "Adding Managers and their reports"
$managerData = Import-Csv "$scriptRoot\$($domainName)-managers.csv"
foreach ($managerEntry in $managerData) {
    set-aduser $managerEntry.manager -Title "Manager"
    get-adgroupmember $managerEntry.Group | Where-Object samaccountname -ne $managerEntry.manager | get-aduser | set-aduser -manager $($managerEntry.manager) -department $managerEntry.Group
    write-log "Added $($managerEntry.manager) as Manager to members of group $($managerEntry.Group)" -severity SUCCESS
}
#endregion
#region Add external Universal Groups to domain local groups
$trustTargetList = (Get-ADTrust -Filter * -Properties Target).Target
forEach ($trustTarget in $trustTargetList) {
    $remoteCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($remoteuser)@$($trustTareget)", (ConvertTo-SecureString $remotePassword -AsPlainText -Force)
    $i = 1
    Do {
        write-log "Verifying domain is online $($trustTarget) domain. Attempt number $($i)" 
        $domaindata = Get-ADDomain -Server $trustTarget -Credential $remoteCredentials 
        $i++
        if (!($domaindata)) {
            start-sleep -Seconds 60
        }
    } until ($domaindata -or $i -eq 21)
    if (!($domaindata)) {
        throw "Unable to get a list of groups from $($trustTarget) domain"
        exit
    }
    write-log "Confirmed domain $($trustTarget) is available" -severity SUCCESS

    write-log "Processing foreign pricipal membership data from file"
    $fpMemberData = Import-Csv "$scriptRoot\$($domainName)-fp-groups.csv" | group -AsHashTable -Property Member
    forEach ($fpGroupName in $fpMemberData.Keys) {
        $LocalGroupArray = $fpMemberData.$fpGroupName.Group
        $fpGroupData = Get-ADGroup -Identity $fpGroupName -Server $trustTarget -Credential $remoteCredentials
        foreach ($localGroup in $LocalGroupArray) {
            Add-ADGroupMember -Identity $localGroup -Members $fpGroupData
            write-log "Added $($fpGroupData.name) to group $($localGroup)" -severity SUCCESS 
        }
    }
    Clear-Variable fpGroupData

}
#endregion
#region create sysvol files and folders gives random
write-log "Creating deparment login script and assign permissions from generic groups"

foreach ($group in $departmentGroups) {
    $_folderResult = New-Item "C:\Windows\sysvol\domain\scripts\$($group.Name)\" -type directory
    write-log "Created directory $($_folderResult.FullName)" -severity SUCCESS
    $_fileREsult = New-Item "C:\Windows\sysvol\domain\scripts\$($group.Name)\logon.bat" -type file
    write-log "Created file $($_fileREsult.FullName)"   -severity SUCCESS
    set-CustomACLs -TargetPath $_folderResult.FullName -IdenitylRefrence "$($domainName)\$($group.SamAccountName)" -FileSystemRights Modify -InheritanceFlags ObjectInherit -PropagationFlags InheritOnly -AccessControlType Allow
    set-CustomACLs -TargetPath $_folderResult.FullName -IdenitylRefrence "$($domainName)\Service Desk Operators" -FileSystemRights FullControl -InheritanceFlags ObjectInherit -PropagationFlags InheritOnly -AccessControlType Allow
}
#endregion
#region SID history
if ($domainFQDN -eq "fabrikamad.com") {
    write-log "Completed customization of domain $($domainFQDN) successfully. Exiting" -severity SUCCESS
    exit
}
write-log "Installing DSInternals module"
Expand-Archive -Path "$($scriptRoot)\DSInternals_v4.4.1.zip" -Force -DestinationPath "C:\Program Files\WindowsPowerShell\Modules\DSInternals"

if (Get-Module -Name DSInternals -ListAvailable) {
    write-log "DS Internals Module Installed successfully" -severity SUCCESS
}
else {
    throw "Failed to install module DSInternals. Failing script"
    exit 
}

foreach ($trustTarget in $trustTargetList) {

    $remoteCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($remoteuser)@$($trustTarget)", (ConvertTo-SecureString $remotePassword -AsPlainText -Force)
    $sidHistoryDB = @()
    get-aduser -Filter 'GivenName -eq "Amari" -or GivenName -eq "Jaden" -or GivenName -eq "Jaylin" -or GivenName -eq "Jadyn"' -Properties SID, GivenName -Server $trustTarget -Credential $remoteCredentials | ForEach-Object {
        $givenName = $psItem.GivenName
        $samAccountName = (get-aduser -Filter * -Properties samAccountName | where { $_.GivenName -eq $givenName }).samAccountName
        $item = New-Object psobject -Property @{
            oldSid         = $PsItem.Sid
            samAccountName = $samAccountName
        }
        $sidHistoryDB += $item
    }
    write-log "Stopping NTDS service to add sidHistory"
    $stopserviceResult = Stop-Service -Name ntds -Force -PassThru
    if ($stopserviceResult.Status -eq 'Stopped') {
        write-log "NTDS service stopped successfully" -severity SUCCESS
    }
    else {
        throw "NTDS service failed to stop. Failing script"
        exit

    }
    foreach ($sidHistory in $sidHistoryDB) {
        Add-ADDBSidHistory -SidHistory $sidHistory.oldSid -SamAccountName $sidHistory.samAccountName  -DatabasePath C:\Windows\NTDS\ntds.dit

        write-log "Addded sidHistory to user $($sidHistory.samAccountName)" -severity SUCCESS

    
    }

    write-log "Starting NTDS service"
    $startServiceResult = Start-Service -Name ntds -PassThru

    if ($startServiceResult.Status -eq 'Running') {
        write-log "NTDS service started succesfully" -severity SUCCESS
    }
    else {
        throw "NTDS failed to start. Failing script"
        exit
    }

   
  

}
#endregion
write-log "Script complete run succesfullt" -severity SUCCESS

