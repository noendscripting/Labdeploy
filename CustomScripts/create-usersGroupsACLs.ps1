[CmdletBinding()]

param(
    [Parameter(Position = 0)]
    [string]$remoteUser,
    [Parameter(Position = 1)]
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
    Write-Host "$($timeStamp) $($severity) $($message)" -ForegroundColor $messageColor
    if (!([string]::IsNullOrEmpty($logfile))) {
        write-output "$($timeStamp) $($severity) $($message)" | Out-File -FilePath $logfile -Encoding ascii -Append
    }


}
Function add-OrganizationalUnits {
    param(
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]$OUList,
        [string]$TargetDomainDN
    )


    #Getting list of OUs filtreing for uniqueness and removing Source Domain Distinguished Name
    write-log "Getting list of domains from file $($OUList)"
    $ImportedOUs = (Get-Content $OUList)
    write-log "Total $($ImportedOus.Count) unique OUs found" -severity SUCCESS
    [int]$TotalAddedOUs = 0 
    # Going over a list 
    ForEach ($importedOU in $ImportedOUs) {
        #Placing OUs into temprary array 
        [string[]]$arrayOU = $importedOU.Split(",")
        #Getting total number of OU branches 
        [int]$ouLength = $arrayOU.Length - 1
        #Setting temp variables
        $tempPath = $null
        $OuName = $null
        #Starting loop to process each OU branch in reverse order form the root Domain DN
        Do {
            #Creating first OU path going form the last ( closest to the domain root) OU branch 
            $tempPath = "$($arrayOU[$ouLength]),$($tempPath)"
            #Checking if OU exists
            If (!([adsi]::Exists("LDAP://$($tempPath)$($TargetDomainDN)"))) {
                #If OU does not exist, verifying this is the first branch under the root
                if ($ouLength -eq $arrayOU.Length - 1) {   
                    #if first branch under the root Domain DN
                    #verifying is not a container
                    if ($arrayOU[$ouLength].Substring(0, 2) -ne "CN") {

                        #Removing OU= or CN from the OU branch
                        $OuName = $arrayOU[$ouLength].Substring(3, ($arrayOU[$ouLength].Length - 3))  
                        #Creating new OU and saving result
                        $result = New-ADOrganizationalUnit -Name $OuName -Path $TargetDomainDN -ProtectedFromAccidentalDeletion $false -PassThru
                        #Outputting Result to log 
                        write-log "Added $($result.DistinguishedName)"
                        $TotalAddedOUs += 1
                    }
                    else {
                        write-log -message "Container $($arrayOU[$ouLength]) needs to be created by a separate process. " -severity WARN
                    }
                }
                else {   
                    #If not the first branch under domain Root DN
                    #Removing OU= or CN from the OU branch
                    $OuName = $arrayOU[$ouLength].Substring(3, ($arrayOU[$ouLength].Length - 3))
                    #Creating new OU and saving result
                    $result = New-ADOrganizationalUnit -Name $OuName -Path $parentPath -ProtectedFromAccidentalDeletion $false  -PassThru
                    write-log "Added $($result.DistinguishedName)" -severity SUCCESS
                    $TotalAddedOUs += 1
                }
            }
            else {
                #If OU already exists, recoding the result.
                write-log "OU $($tempPath)$($TargetDomainDN) already exists"
            }
            #Creating parent path for the next OU branch 
            $parentPath = "$($tempPath)$($TargetDomainDN)"
            #Verify that result variable is not empty and clearing contents
            if ($null -ne $result) {
                Clear-Variable result
            }
            #Substruting from OU iterator to go to next branch in the loop
            $ouLength -= 1
        } while ($ouLength -ge 0) # terminate after OU iterator is less than 0
    }
    write-log "Total Added $($TotalAddedOUs)" -severity SUCCESS
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
function Set-OuDelegatiion {
    param(
        [string]$group,
        [string]$csvRightsList,
        [string]$targetOU
    ) 
    
    $importedPermissions = Import-Csv $csvRightsList
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
#region configuring enabling WinRM with certbased auth and configuring firewall
<#$Cert = New-SelfSignedCertificate -CertstoreLocation Cert:\LocalMachine\My -DnsName $env:COMPUTERNAME
Enable-PSRemoting -SkipNetworkProfileCheck -Force
New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $Cert.Thumbprint -Force
New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -Name "Windows Remote Management (HTTPS-In)" -Profile Any -LocalPort 5986 -Protocol TCP
Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True -LogIgnored True #>
#endregion
#region setting local domain variables
$scriptRoot = split-path $myInvocation.MyCommand.Source -Parent
$domainDN = (get-addomain).distinguishedname
$domainName = (Get-ADDomain).NetbiosName
$companyName = (Import-csv "$($scriptRoot)\$($domainName)-users.csv" | Select-Object Company -Unique ).Company
#endregion
#region adding OUs
add-OrganizationalUnits -OUList "$($scriptRoot)\ous.txt" -TargetDomainDN $domainDN
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
#region creating deparmnet groups
write-log "Creating deparatment groups"
$groupsOU = "OU=Security Groups,OU=Groups,$($domainDN)"
$_new_groups = Get-Content "$($scriptRoot)\groups.txt" 
$_new_groups | ForEach-Object {
    New-ADGroup $_ -SamAccountName $_ -DisplayName "$_" -GroupScope Global -GroupCategory Security -Path $groupsOU
    write-log "Created departmnet group $($_)" -severity SUCCESS
}
#endregion
#region creating priveleged groups
write-log "Creating privilged groups"
New-ADGroup tier0admins -SamAccountName tier0admins -DisplayName "tier0admins" -GroupScope Global -GroupCategory Security -Path "OU=Groups,OU=Tier 0,OU=Admin,$($domainDN)"
New-ADGroup "AD Infrastructure Engineers" -SamAccountName "AD Infrastructure Engineers" -DisplayName "AD Infrastructure Engineers" -GroupScope Global -GroupCategory Security -Path "OU=Groups,OU=Tier 0,OU=Admin,$($domainDN)"
New-ADGroup tier1admins -SamAccountName tier1admins -DisplayName "tier1admins" -GroupScope Global -GroupCategory Security -Path "OU=Groups,OU=Tier 1,OU=Admin,$($domainDN)"
New-ADGroup "Tier1 Server Maintenance" -SamAccountName "Tier1 Server Maintenance" -DisplayName "Tier1 Server Maintenance" -GroupScope Global -GroupCategory Security -Path "OU=Groups,OU=Tier 1,OU=Admin,$($domainDN)"
New-ADGroup "tier2admins" -SamAccountName "tier2admins" -DisplayName "tier2admins" -GroupScope Global -GroupCategory Security -Path "OU=Groups,OU=Tier 2,OU=Admin,$($domainDN)"
New-ADGroup "Service Desk Operators" -SamAccountName "Service Desk Operators" -DisplayName "Service Desk Operators" -GroupScope Global -GroupCategory Security -Path "OU=Groups,OU=Tier 2,OU=Admin,$($domainDN)"

write-log "Adding AD Infrastructure Engineers to Domain Admins"
$privlegedADGroup = Get-ADGroup "AD Infrastructure Engineers"
Get-ADGroup "Domain Admins" | Add-ADGroupMember -Members $privlegedADGroup
#endregion
#region Adding OU delegations
write-log "Setting up delegations in OUs"

0..2 | ForEach-Object {
    Set-OuDelegatiion -group "tier$($PSItem)admins" -csvRightsList "$($scriptRoot)\ou-rights.csv" -targetOU "OU=Tier $($PsItem),OU=Admin,$($domainDN)"
}
Set-OuDelegatiion -group "Service Desk Operators" -csvRightsList "$($scriptRoot)\ou-rights.csv" -targetOU "OU=Enabled Users,OU=User Accounts, $($domainDN)"
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
    $_department = $_new_groups | get-random
    $_ | Set-ADUser  -department $_department
    Get-ADgroup $_department | Add-ADGroupMember -members $_
    write-log "Added user $($_) to Depratmnet group $($_department)" -severity SUCCESS
}
#endregion
#region create manager\report entries for each department
write-log "Adding Managers and their reports"
$_new_groups | ForEach-Object { $gname = $_
    $Manager = get-adgroupmember $gname  | get-random | get-aduser 
    $Manager | Set-ADUser  -Title "Manager"
    get-adgroupmember $gname | Where-Object samaccountname -ne $manager.samaccountname | get-aduser | set-aduser -manager $($manager.distinguishedname) -department $gname
    write-log "Added $($manager.Name) as Manager to members of group $($gname)" -severity SUCCESS
}
#endregion
#region create privleged users
write-log "Creating Tier 0 "
add-PrivelegedUsers -ou "OU=Accounts,OU=Tier 0,OU=Admin, $($domainDN)" -prefix "EA" -Tier 0
write-log "Creating Tier 1 "
add-PrivelegedUsers -ou "OU=Accounts,OU=Tier 1,OU=Admin, $($domainDN)" -prefix "SA"  -Tier 1
write-log "Creating Tier 2 "
add-PrivelegedUsers -ou "OU=Accounts,OU=Tier 2,OU=Admin, $($domainDN)" -prefix "WSA"  -Tier 2
#endregion
#region add privleged users to privelged groups
add-UsersToPrivelgedGroups -groups "tier0admins", "AD Infrastructure Engineers" -ou "OU=Accounts,OU=Tier 0,OU=Admin, $($domainDN)"
add-UsersToPrivelgedGroups -groups "tier1admins", "Tier1 Server Maintenance" -ou "OU=Accounts,OU=Tier 1,OU=Admin, $($domainDN)"
add-UsersToPrivelgedGroups -groups "tier2admins", "Service Desk Operators" -ou "OU=Accounts,OU=Tier 2,OU=Admin, $($domainDN)"
#endregion
#region populating generic groups with users
write-log "Adding random users to Universal and Local groups"
$_groups = (get-adgroup -filter 'samaccountname -like "grp-*"').distinguishedname
get-aduser -filter * -searchbase $usersOU | ForEach-Object {
    $_group_count = Get-Random -Minimum 1 -Maximum 10
    $_user = $PSItem
    $_groups | Get-Random -Count $_group_count | ForEach-Object {

        Add-ADGroupMember -Identity $PSItem -Members $_user
        write-log "Addded user $($_user.display) to group $($PSItem)"
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
    $i = 0
    Do {
        $foreignGroups = Get-ADGroup -Filter 'name -like "*universal*"' -Server $trustTarget -Credential $remoteCredentials | Get-Random -Count (Get-Random -Minimum 5 -Maximum 25)
        start-sleep -Seconds 60
    } until ($foreignGroups.count -gt 0 -or $i -eq 10)
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

foreach ($group in $_new_groups) {
    $_folderResult = New-Item "C:\Windows\sysvol\domain\scripts\$($group)\" -type directory
    write-log "Created directory $($_folderResult.FullName)"
    $_fileREsult = New-Item "C:\Windows\sysvol\domain\scripts\$($group)\logon.bat" -type file
    write-log "Created file $($_fileREsult.FullName)"   
    set-CustomACLs -TargetPath $_folderResult.FullName -IdenitylRefrence "$($domainName)\Service Desk Operators" -FileSystemRights FullControl -InheritanceFlags ObjectInherit -PropagationFlags InheritOnly -AccessControlType Allow
}
#endregion
#region Import GPOs
$zipFileData = Get-ChildItem "$($scriptRoot)\*.zip" | Select-Object FullName, BaseName
if ([string]::IsNullOrEmpty($zipFileData.FullName)) {
    throw "Failed find zip file with GPO backup"

}
write-log "Found GPO backup ZIP file at $($zipFileData.FullName)"
#$tierOneGroupData = get-adgroup 'Tier1 Server Maintenance' -Properties Name, SID
#$groupName = "$($domainName)\$($tierOneGroupData.name)"
#$groupSID = $tierOneGroupData.SID.ToString()

Expand-Archive -Path $zipFileData.fullname -Force -DestinationPath $scriptRoot

#$configXMPath = "$($scriptRoot)\$($zipFileData.basename)\DomainSysvol\GPO\Machine\Preferences\Groups\Groups.xml"
#if ([string]::IsNullOrEmpty($configXMPath)) {
#    throw "Failed extract zip file with GPO backup"

#}
#[xml]$GPOSettings = Get-Content $configXMPath

#$GPOSettings.Groups.Group.Properties.Members.Member.Name = $groupName
#write-log "Set Group Name in GPO Prefrences to $($groupName)"
#$GPOSettings.Groups.Group.Properties.Members.Member.SID = $groupSID
#write-log "Set Group SID in GPO Prefrences to $($groupSID)"
#$GPOSettings.Save($configXMPath)
$importgpresult = import-gpo -BackupGpoName 'Server Admin GPO' -Path "$($scriptRoot)" -CreateIfNeeded -TargetName 'Server Admin GPO'
write-log "GPO $($importgpresult.DisplayName) added with id $($importgpresult.is)" -severity SUCCESS
$linkedGPOresult = New-GPLink -Name 'Server Admin GPO' -Target $domainDN 
write-log "GPO $($linkedGPOresult.DisplayName) linked to $($linkedGPOresult.Target)" -severity SUCCESS
#endregion







