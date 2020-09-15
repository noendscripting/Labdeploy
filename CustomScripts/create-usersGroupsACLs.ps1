[CmdletBinding()]

param()
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
    write-log "Total $($ImportedOus.Count) unique OUs found"
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
                        write-log -message "Container $($arrayOU[$ouLength]) needs to be created by same process as original. " -severity WARN
                    }
                }
                else {   
                    #If not the first branch under domain Root DN
                    #Removing OU= or CN from the OU branch
                    $OuName = $arrayOU[$ouLength].Substring(3, ($arrayOU[$ouLength].Length - 3))
                    #Creating new OU and saving result
                    $result = New-ADOrganizationalUnit -Name $OuName -Path $parentPath -ProtectedFromAccidentalDeletion $false  -PassThru
                    write-log "Added $($result.DistinguishedName)"
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
            if ($result -ne $null) {
                Clear-Variable result
            }
            #Substruting from OU iterator to go to next branch in the loop
            $ouLength -= 1
        } while ($ouLength -ge 0) # terminate after OU iterator is less than 0
    }
    write-log "Total Added $($TotalAddedOUs)"
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
            write-log "Added priveleged Tier $($Tier) account $($PSItem.name)"
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
            write-log "Added $($PSItem.name) to $($group)"
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
        write-log "Added group $($importedPermission.IdentityReference) permissions $($importedPermission.ActiveDirectoryRights) to $($targetOU)"
        Clear-Variable rightsObject, ACL
    
    }

}

function set-CustomACLs
{
     param(
         [string]$TargetPath,
         [string]$IdenitylRefrence,
         [string]$FileSystemRights,
         [string]$InheritanceFlags,
         [string]$PropagationFlags,
         [string]$AccessControlType
     )

    $acl = Get-Acl $TargetPath
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($IdenitylRefrence,$FileSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType)
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
#region setting local domain variables
$domainDN = (get-addomain).distinguishedname
$domainName = (Get-ADDomain).NetbiosName
$companyName = (Import-csv "$PSScriptRoot\$($domainName)-users.csv" | Select-Object Company -Unique ).Company

#endregion
#region adding OUs
add-OrganizationalUnits -OUList "$($PSScriptRoot)\ous.txt" -TargetDomainDN $domainDN
#endregion
#region adding users 
write-log "Adding user to $($domainName)"

foreach ($user in (import-csv "$PSScriptRoot\$($domainName)-users.csv")) {
    $name = $user.first + " " + $user.last

    $newUserObject = @{

        Name              = $name
        City              = $user.city
        Company           = $companyName
        Country           = 'US'
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
        path              = "OU=Enabled Users,OU=User Accounts, $($domainDN)"
        AccountPassword   = (ConvertTo-SecureString -AsPlainText "!Th1sn33dsto b3ash@rdas1tc@n" -Force)
        Enabled           = $true
        
    }
    New-ADUser @newUserObject
    write-log "Added user $($name)" 
    Clear-Variable name
}
#endregion
#region creating deparmnet groups
write-log "Creating deparatment group"
#$_ou = "OU=Security Groups,OU=Groups,$($domainDN)"
$_new_groups = Get-Content "$($PSScriptRoot)\groups.txt" 
$_new_groups | ForEach-Object {
    New-ADGroup $_ -SamAccountName $_ -DisplayName "$_" -GroupScope Global -GroupCategory Security -Path "OU=Security Groups,OU=Groups,$($domainDN)"
    write-log "Created departmnet group $($_)"
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
#region Adding OU delegattions
write-log "Setting up delegations in OUs"

0..2 | ForEach-Object {
    Set-OuDelegatiion -group "tier$($PSItem)admins" -csvRightsList "$($PSScriptRoot)\ou-rights.csv" -targetOU "OU=Tier $($PsItem),OU=Admin,$($domainDN)"
}
Set-OuDelegatiion -group "Service Desk Operators" -csvRightsList "$($PSScriptRoot)\ou-rights.csv" -targetOU "OU=Enabled Users,OU=User Accounts, $($domainDN)"
#endregion
#region creating random gneral groups
write-log "Creating random general groups"
1..(Get-Random -Minimum 1 -Maximum 40) | ForEach-Object {
    $groupName = "grp-$($companyName)-general-$($psitem)"
    New-ADGroup $groupName -SamAccountName $groupName -DisplayName $groupName -GroupScope Global -GroupCategory Security -Path "OU=Security Groups,OU=Groups,$($domainDN)"
    write-log "Created general group $($groupName)"
}
#endregion
#region populatuing departmnent groups with users and adding departmnet value to the user properties
get-aduser -filter * -SearchBase "OU=Enabled Users,OU=User Accounts, $($domainDN)" | ForEach-Object {
    $_department = $_new_groups | get-random
    $_ | Set-ADUser  -department $_department
    Get-ADgroup $_department | Add-ADGroupMember -members $_
    write-log "Added user $($_) to Depratmnet group $($_department)"
}
#endregion
#region create manager\report entries for each department
write-log "Adding Managers and their reports"
$_new_groups | ForEach-Object { $gname = $_
    $Manager = get-adgroupmember $gname  | get-random | get-aduser 
    $Manager | Set-ADUser  -Title "Manager"
    get-adgroupmember $gname | Where-Object samaccountname -ne $manager.samaccountname | get-aduser | set-aduser -manager $($manager.distinguishedname) -department $gname
    write-log "Added $($manager.Name) as Manager to members of group $($gname)"
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
write-log "Adding random users to generic groups"
$_ou = "OU=Enabled Users,OU=User Accounts, $($domainDN)"
$_groups = (get-adgroup -filter 'samaccountname -like "grp-*"').distinguishedname
get-aduser -filter * -searchbase $_ou | ForEach-Object {
    $_group_count = Get-Random -Minimum 1 -Maximum 10
    $_user = $PSItem
    $_groups | Get-Random -Count $_group_count | ForEach-Object {

        Add-ADGroupMember -Identity $PSItem -Members $_user
        write-log "Addded user $($_user.display) to group $($PSItem)"
    }
    Clear-Variable _user
    <#for ($i = 1; $i -le $_group_count; $i++) {
        
       
    }#>
}
#endregion
#region populating generic groups with other generic groups
write-log "Nesting random generic groups inside each outher"
$groups = get-adgroup -filter 'samaccountname -like "grp-*"'
get-adgroup -filter 'samaccountname -like "grp-*"' | ForEach-Object {
    $_.DistinguishedName
    $_group_count = Get-Random -Minimum 1 -Maximum 10
    $_group_count
    for ($i = 1; $i -le $_group_count; $i++) {
        
        Add-ADGroupMember -Identity $($groups | get-random) -Members $_
    }
  Write-log "Added $($_group_count) to group $($_.Name)"
}
#endregion 
#region create sysvol files and folders gives random
write-log "Creating deparment login script and assign permissions from generic groups"

foreach($group in $_new_groups)
{
    $_folderResult = New-Item "C:\Windows\SYSVOL\domain\scripts\$($group)\" -type directory
    write-log "Created directory $($_folderResult.FullName)"
    $_fileREsult = New-Item "C:\Windows\SYSVOL\domain\scripts\$($group)\logon.bat" -type file
    write-log "Created file $($_fileREsult.FullName)"   
    set-CustomACLs -TargetPath $_folderResult.FullName -IdenitylRefrence "$($domainName)\Service Desk Operators" -FileSystemRights FullControl -InheritanceFlags ObjectInherit -PropagationFlags InheritOnly -AccessControlType Allow
}
#endregion

#region Import GPOs
import-gpo -BackupGpoName "Server Admins GPO" -TargetName TestGPO -path $PSScriptRoot







