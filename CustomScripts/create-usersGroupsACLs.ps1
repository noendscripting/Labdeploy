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
        write-log "Added group $($importedPermission.IdentityReference) permissions $($importedPermission.ActiveDirectoryRights) to $($targetOU)" -severity SUCCESS
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
function add-GroupMemberships {
    param (
        $groups,
        $members,
        $radomFactor
    )
    $members | ForEach-Object {
        for ($i = 1; $i -le $radomFactor; $i++) {
            $addResult = Add-ADGroupMember -Identity $($Groups | get-random) -Members $PSItem -PassThru
            write-log "Added $($PSItem.Name) to group $($addResult.Name)" -severity SUCCESS
        }
    }


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
$companyName = (Import-csv "$($scriptRoot)\$($domainName)-users.csv" | Select-Object Company -Unique ).Company
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
        Company           = $companyName
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
#region getting deparmnet groups
write-log "Creating deparatment groups"
$groupsOU = "OU=Security Groups,OU=Groups,$($domainDN)"
$departmentGroups = get-adgroup -filter * -SearchBase $groupsOU
#endregion
#region creating priveleged groups
write-log "Creating privilged groups"
New-ADGroup "tier2admins" -SamAccountName "tier2admins" -DisplayName "tier2admins" -GroupScope Global -GroupCategory Security -Path $groupsOU
New-ADGroup "Service Desk Operators" -SamAccountName "Service Desk Operators" -DisplayName "Service Desk Operators" -GroupScope Global -GroupCategory Security -Path $groupsOU
#endregion
#region Adding OU delegations
write-log "Setting up delegations in OUs"
Set-OuDelegation -group "Service Desk Operators" -jsRightsObject $jsonDelegationDetails -targetOU "OU=Enabled Users,OU=User Accounts, $($domainDN)" 
#endregion
#region creating random local groups
write-log "Creating random local groups"
1..(Get-Random -Minimum 1 -Maximum 40) | ForEach-Object {
    $groupNameLocal = "grp-$($companyName)-local-$($psitem)"
    New-ADGroup $groupNameLocal -SamAccountName $groupNameLocal -DisplayName $groupNameLocal -GroupScope DomainLocal -GroupCategory Security -Path $groupsOU
    write-log "Created local group $($groupNameLocal)" -severity SUCCESS
}
#endregion
#region creating random universal groups
write-log "Creating random universal groups"
1..(Get-Random -Minimum 1 -Maximum 40) | ForEach-Object {
    $groupNameUniversal = "grp-$($companyName)-universal-$($psitem)"
    New-ADGroup $groupNameUniversal -SamAccountName $groupNameUniversal -DisplayName $groupNameUniversal -GroupScope Universal -GroupCategory Security -Path $groupsOU
    write-log "Created general group $($groupName)" -severity SUCCESS
}
#endregion
#region populatuing departmnent groups with users and adding departmnet value to the user properties
get-aduser -filter * -SearchBase $usersOU | ForEach-Object {
    $departmentGroup = $departmentGroups | get-random
    $_ | Set-ADUser  -department $departmentGroup.Name
    Add-ADGroupMember -members $_ -Identity $departmentGroup.SID
    write-log "Added user $($_) to Depratmnet group $($departmentGroup.Name)" -severity SUCCESS
}
#endregion
#region create manager\report entries for each department
write-log "Adding Managers and their reports"
$departmentGroups.Name | ForEach-Object { $gname = $_
    $Manager = get-adgroupmember $gname  | get-random | get-aduser 
    $Manager | Set-ADUser  -Title "Manager"
    get-adgroupmember $gname | Where-Object samaccountname -ne $manager.samaccountname | get-aduser | set-aduser -manager $($manager.distinguishedname) -department $gname
    write-log "Added $($manager.Name) as Manager to members of group $($gname)" -severity SUCCESS
}
#endregion
#region add privleged users to privelged groups
add-UsersToPrivelgedGroups -groups "tier2admins", "Service Desk Operators" -ou $groupsOU
#endregion
#region populating generic groups with users
write-log "Adding random users to Universal and Local groups"
$_groups = (get-adgroup -filter 'samaccountname -like "grp-*"').distinguishedname
get-aduser -filter * -searchbase $usersOU | ForEach-Object {
    $_group_count = Get-Random -Minimum 1 -Maximum 10
    $_user = $PSItem
    $_groups | Get-Random -Count $_group_count | ForEach-Object {

        Add-ADGroupMember -Identity $PSItem -Members $_user
        write-log "Addded user $($_user.Name) to group $($PSItem)" -severity SUCCESS
    }
    Clear-Variable _user
}
$allGenericGroups = (get-adgroup -filter 'samaccountname -like "grp-*"')
$allUsers = get-aduser -filter * -searchbase $usersOU 
$_groupRandomcount = Get-Random -Minimum 1 -Maximum 10
add-GroupMemberships -groups $allGenericGroups -members $allUsers -radomFactor $_groupRandomcount
Clear-Variable _groupRandomcount
#endregion
#region populating Universal groups with other Universal groups
write-log "Nesting random generic groups inside each other"
$universallGroups = get-adgroup -filter 'samaccountname -like "*Universal*"'
$_groupRandomcount = Get-Random -Minimum 1 -Maximum 10
add-GroupMemberships -groups $universallGroups -members $universallGroups -radomFactor $_groupRandomcount
Clear-Variable _groupRandomcount
#endregion
#region populating domain local groups with  generic groups
write-log "Nesting random generic groups inside  local groups"
$localGroups = get-adgroup -filter 'samaccountname -like "*local*"'
$_groupRandomcount = Get-Random -Minimum 1 -Maximum 10
add-GroupMemberships -groups $localGroups -members $universallGroups -randomFactor $_groupRandomcount
Clear-Variable _groupRandomcount
#endregion
#region Add external Universal Groups to domain local groups
$trustTargetList = (Get-ADTrust -Filter * -Properties Target).Target
forEach ($trustTarget in $trustTargetList) {
    $remoteCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($remoteuser)@$($trustTareget)", (ConvertTo-SecureString $remotePassword -AsPlainText -Force)
    write-log "Getting list of groups from $($trustTarget) domain" 
    $i = 1
    Do {
        write-log "Getting list of groups from $($trustTarget) domain. Attempt number $($i)" 
        $foreignGroups = Get-ADGroup -Filter 'name -like "*universal*"' -Server $trustTarget -Credential $remoteCredentials | Get-Random -Count (Get-Random -Minimum 5 -Maximum 25)
        $i++
        if (!($foreignGroups.count -gt 0))
        {
            start-sleep -Seconds 60
        }
    } until ($foreignGroups.count -gt 0 -or $i -eq 21)
    if ($foreignGroups.count -eq 0) {
        throw "Unable to get a list of groups from $($trustTarget) domain"
        exit
    }
    write-log "Obtained $($foreignGroups.count) from $($trustTarget)"
    $_groupRandomcount = Get-Random -Minimum 2 -Maximum 10
    add-GroupMemberships -radomFactor $_groupRandomcount -members $foreignGroups -groups $localGroups
}
#endregion
#region create sysvol files and folders gives random
write-log "Creating deparment login script and assign permissions from generic groups"

foreach ($group in $departmentGroups) {
    $_folderResult = New-Item "C:\Windows\sysvol\domain\scripts\$($group.Name)\" -type directory
    write-log "Created directory $($_folderResult.FullName)" -severity SUCCESS
    $_fileREsult = New-Item "C:\Windows\sysvol\domain\scripts\$($group.Name)\logon.bat" -type file
    write-log "Created file $($_fileREsult.FullName)"   -severity SUCCESS
    set-CustomACLs -TargetPath $_folderResult.FullName -IdenitylRefrence "$($domainName)\$($group.Name)" -FileSystemRights FullControl -InheritanceFlags ObjectInherit -PropagationFlags InheritOnly -AccessControlType Allow
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

    $remoteCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($remoteuser)@$($trustTareget)", (ConvertTo-SecureString $remotePassword -AsPlainText -Force)
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

