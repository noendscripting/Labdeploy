function write-log
{ 


param(
    [Parameter(ValueFromPipeline=$true,Mandatory=$true)]
    $message,
    [ValidateSet("ERROR","INFO","WARN")]
    $severity,
    $logfile

)

$WhatIfPreference=$false
$timeStamp = get-date -UFormat %Y%m%d-%I:%M:%S%p
switch ($severity)
 {

  "INFO" {$messageColor = "Green"}
  "ERROR" {$messageColor = "Red"}
  "WARN" {$messageColor = "Yellow"}
    
 }
 Write-Host "$($timeStamp) $($severity) $($message)" -ForegroundColor $messageColor
 if ($logfile.length -ge 0)
 {
    write-output "$($timeStamp) $($severity) $($message)" | Out-File -FilePath $logfile -Encoding ascii -Append
 }



}


Function add-OrganizationalUnits
{
 param(
# Parameter help description
[Parameter(Mandatory=$true)]
[string]$OUList,
[string]$TargetDomainDN
 )


#Getting list of OUs filtreing for uniqueness and removing Source Domain Distinguished Name
write-log "Getting list of domains from file $($OUList)"
$ImportedOUs = (Get-Content $OUList)
write-log "Total $($ImportedOus.Count) unique OUs found"
[int]$TotalAddedOUs = 0 
# Going over a list 
ForEach ($importedOU in $ImportedOUs)
{
    #Placing OUs into temprary array 
    [string[]]$arrayOU = $importedOU.Split(",")
    #Getting total number of OU branches 
    [int]$ouLength=$arrayOU.Length-1
    #Setting temp variables
    $tempPath = $null
    $OuName = $null
    #Starting loop to process each OU branch in reverse order form the root Domain DN
    Do {
        #Creating first OU path going form the last ( closest to the domain root) OU branch 
        $tempPath = "$($arrayOU[$ouLength]),$($tempPath)"
        #Checking if OU exists
        If (!([adsi]::Exists("LDAP://$($tempPath)$($TargetDomainDN)")))
        {
            #If OU does not exist, verifying this is the first branch under the root
            if ($ouLength -eq $arrayOU.Length -1)
            {   
                #if first branch under the root Domain DN
                #verifying is not a container
                if ($arrayOU[$ouLength].Substring(0,2) -ne "CN")
                {

                #Removing OU= or CN from the OU branch
                $OuName = $arrayOU[$ouLength].Substring(3,($arrayOU[$ouLength].Length-3))  
                #Creating new OU and saving result
                $result = New-ADOrganizationalUnit -Name $OuName -Path $TargetDomainDN -ProtectedFromAccidentalDeletion $false -PassThru
                #Outputting Result to log 
                write-log "Added $($result.DistinguishedName)"
                $TotalAddedOUs+=1
             }
             else
             {
                write-log -message "Container $($arrayOU[$ouLength]) needs to be created by same process as original. " -severity WARN
             }
            }
            else
            {   
                #If not the first branch under domain Root DN
                #Removing OU= or CN from the OU branch
                $OuName = $arrayOU[$ouLength].Substring(3,($arrayOU[$ouLength].Length-3))
                #Creating new OU and saving result
                $result = New-ADOrganizationalUnit -Name $OuName -Path $parentPath -ProtectedFromAccidentalDeletion $false  -PassThru
                write-log "Added $($result.DistinguishedName)"
                $TotalAddedOUs+=1
            }
        }
        else
        {
            #If OU already exists, recoding the result.
            write-log "OU $($tempPath)$($TargetDomainDN) already exists"
        }
        #Creating parent path for the next OU branch 
        $parentPath = "$($tempPath)$($TargetDomainDN)"
        #Verify that result variable is not empty and clearing contents
        if ($result -ne $null)
        {
            Clear-Variable result
        }
        #Substruting from OU iterator to go to next branch in the loop
        $ouLength-=1
    } while ($ouLength -ge 0) # terminate after OU iterator is less than 0
}
write-log "Total Added $($TotalAddedOUs)"
}

#setting local domain variables
$domainDN = (get-addomain).distinguishedname
$domainName = (Get-ADDomain).NetbiosName
$companyName = ((Get-ADDomain).Forest.Split("."))[0]


#adding OUs
add-OrganizationalUnits -OUList "./ous.csv" -TargetDomainDN $domainDN


#adding users 
write-log "Adding user to $($domainName)"

foreach($user in (import-csv "./$($domainName)users.csv")){
    $name = $user.first + " " + $user.last

    $newUserObject = @{

    Name = $name
    City = $user.city
    Company = $companyName
    Country = 'US'
    EmailAddress = $user.email
    GivenName = $user.first
    MobilePhone = $user.phone
    OfficePhone = $user.phone
    PostalCode = $user.zip
    SamAccountName = $user.samaccountname
    State = $user.state
    StreetAddress = $user.Street
    Surname = $user.last
    UserPrincipalName = $user.email
    path = "OU=Enabled Users,OU=User Accounts, $($domainDN)"
    AccountPassword = (ConvertTo-SecureString -AsPlainText "!Th1sn33dsto b3ash@rdas1tc@n" -Force)
    Enabled = $true
        
    }
    Try {

        New-ADUser @newUserObject
        write-log "Added user $($name)" 
    }
    Catch 
    {
        write-log "$($Error[0].ErrorDetails)"
        throw

    }
    Clear-Variable name
}

#creating deparmnet groups
write-log "Creating deparatment group"
$_ou = "OU=Security Groups,OU=Groups,$($domainDN)"
$_new_groups = @("Logistics","Information Technology","IT Support","Strategic Information Systems","Data Entry","Research and Development","Strategic Sourcing","Purchasing","Strategic Sourcing","Operations","Public Relations","Corporate Communications","Advertising","Market Research","Strategic Marketing","Customer service","Telesales","Account Management","Marketing","Sales","Payroll","Recruitment","Training","Human Resource","Accounting","Financial")
$_new_groups | ForEach-Object{
    
    Try{
        New-ADGroup $_ -SamAccountName $_ -DisplayName "$_" -GroupScope Global -GroupCategory Security -Path $_ou
        write-log "Created departmnet group $($_)"
    }
    Catch
    {
        write-log "$($Error[0].ErrorDetails)"
        throw
    }
}
#creating random gneral groups
write-log "Creating random general groups"
"grp-$($companyName)-general" | ForEach-Object { $_count = $(Get-Random -Minimum 1 -Maximum 40)
    for ($i=1; $i -le $_count; $i++) {
        $_gn = $(Get-Random -Minimum 1 -Maximum 400)
        Try{
            New-ADGroup "$($_)-$_gn" -SamAccountName "$($_)-$_gn" -DisplayName "$($_)-$_gn)" -GroupScope Global -GroupCategory Security -Path $_ou
            write-log "Created general group $($_)"
        }
        Catch
        {
            write-log "$($Error[0].ErrorDetails)"
        throw
        }
    }
}

#populatuing departmnent groups with users
get-aduser -filter * -SearchBase "OU=Enabled Users,OU=User Accounts, $($domainDN)" | ForEach-Object {
    $_department = $_new_groups | get-random
    $_ | Set-ADUser  -department $_department
    Get-ADgroup $_department | Add-ADGroupMember -members $_
}

#create Tier 0 users
write-log "Creating Tier 0 "
$_ou = "OU=Accounts,OU=Tier 0,OU=Admin, $($domainDN)"
$_members = get-adgroupmember "StrategicInformationSystems" 
for ($i=1; $i -le 5; $i++) {
      get-aduser $($_members | get-random) -properties * | ForEach-Object{
        Try {
            New-ADUser -Name $_.name -displayname $_.name -userprincipalname "EA$($_.samaccountname)@$((get-addomain).dnsroot)" -City $_.city -Company "Contoso" -Country US -EmailAddress $_.EmailAddress -GivenName $_.GivenName -MobilePhone $_.mobile -OfficePhone $_.OfficePhone -PostalCode $_.PostalCode -description "Enterprise Admin Account" -SamAccountName "EA$($_.samaccountname)" -State $_.state -StreetAddress $_.StreetAddress -Surname $_.Surname -path $_ou -AccountPassword (ConvertTo-SecureString -AsPlainText "!Th1sn33dsto b3ash@rdas1tc@n" -Force) -Enabled $true
        }
        Catch {
            write-log "$($Error[0].ErrorDetails)"
        throw

        }
      }    
}

#add users to the Domain Admins Group
get-aduser -filter * -searchbase $_ou | ForEach-Object {
    get-adgroup "Domain Admins" | Add-ADGroupMember -members $_
}


$_ou = "OU=Accounts,OU=Tier 1,OU=Admin, $($domainDN)"
$_members = get-adgroupmember "StrategicInformationSystems" 
for ($i=1; $i -le 5; $i++) {
      get-aduser $($_members | get-random) -properties * | ForEach-Object{
        $_
        New-ADUser -Name $_.name -displayname $_.name -userprincipalname "SA$($_.samaccountname)@$((get-addomain).dnsroot)" -City $_.city -Company "Contoso" -Country US -EmailAddress $_.EmailAddress -GivenName $_.GivenName -MobilePhone $_.mobile -OfficePhone $_.OfficePhone -PostalCode $_.PostalCode -description "Server Admin Account" -SamAccountName "SA$($_.samaccountname)" -State $_.state -StreetAddress $_.StreetAddress -Surname $_.Surname -path $_ou -AccountPassword (ConvertTo-SecureString -AsPlainText "!Th1sn33dsto b3ash@rdas1tc@n" -Force) -Enabled $true
      } 
}

"tier1admins","Tier1ServerMaintenance" | ForEach-Object{ $_group = $_
    get-aduser -filter * -searchbase $_ou | ForEach-Object {
        get-adgroup $_group | Add-ADGroupMember -members $_
    }
}

$_ou = "OU=Accounts,OU=Tier 2,OU=Admin, $($domainDN)"
$_members = get-adgroupmember "StrategicInformationSystems" 
for ($i=1; $i -le 5; $i++) {
      get-aduser $($_members | get-random) -properties * | ForEach-Object{
        $_
        New-ADUser -Name $_.name -displayname $_.name -userprincipalname "WSA$($_.samaccountname)@$((get-addomain).dnsroot)" -City $_.city -Company "Contoso" -Country US -EmailAddress $_.EmailAddress -GivenName $_.GivenName -MobilePhone $_.mobile -OfficePhone $_.OfficePhone -PostalCode $_.PostalCode -description "Desktop Admin Account" -SamAccountName "WSA$($_.samaccountname)" -State $_.state -StreetAddress $_.StreetAddress -Surname $_.Surname -path $_ou -AccountPassword (ConvertTo-SecureString -AsPlainText "!Th1sn33dsto b3ash@rdas1tc@n" -Force) -Enabled $true
      } 
}

"tier2admins","ServiceDeskOperators" | ForEach-Object{ $_group = $_
    get-aduser -filter * -searchbase $_ou | ForEach-Object {
        get-adgroup $_group | Add-ADGroupMember -members $_
    }
}

$_ou = "OU=Enabled Users,OU=User Accounts, $($domainDN)"
$_groups = (get-adgroup -filter 'samaccountname -like "grp-*"').distinguishedname
get-aduser -filter * -searchbase $_ou | ForEach-Object{
    $_.DistinguishedName
    $_group_count = Get-Random -Minimum 1 -Maximum 10
    $_group_count
    for ($i=1; $i -le $_group_count; $i++) {
        
        Add-ADGroupMember -Identity $($_groups | get-random) -Members $_
    }
}

$groups = get-adgroup -filter 'samaccountname -like "grp-*"'
get-adgroup -filter 'samaccountname -like "grp-*"' | ForEach-Object{
    $_.DistinguishedName
    $_group_count = Get-Random -Minimum 1 -Maximum 10
    $_group_count
    for ($i=1; $i -le $_group_count; $i++) {
        
        Add-ADGroupMember -Identity $($groups | get-random) -Members $_
    }
}


#create sysvol files and folders gives random
$_new_groups | foreach {
    New-Item "C:\Windows\SYSVOL\domain\scripts\$($_)\" -type directory
    New-Item "C:\Windows\SYSVOL\domain\scripts\$($_)\logon.bat" -type file
    $groups = get-adgroup -filter 'samaccountname -like "grp-files*"'
    $_count = $(Get-Random -Minimum 0 -Maximum 6)
    for ($i=1; $i -le $_count; $i++) {
        $acl = Get-Acl "C:\Windows\SYSVOL\domain\scripts\$($_)"
        $permission = "$((get-addomain).name)\$(($groups | get-random).samaccountname)","FullControl","Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule)
        $acl | Set-Acl "C:\Windows\SYSVOL\domain\scripts\$($_)"
        $acl | Set-Acl "C:\Windows\SYSVOL\domain\scripts\$($_)\logon.bat"
    }
}

#domain controller random domain admin file rights
Add-WindowsFeature RSAT-AD-PowerShell

New-Service -Name "Generic Service" -BinaryPathName "C:\WINDOWS\System32\svchost.exe -k netsvcs"

#fileshare
$_new_groups = "Logistics","Information Technology","IT Support","Strategic Information Systems","Data Entry","Research and Development","Strategic Sourcing","Purchasing","Strategic Sourcing","Operations","Public Relations","Corporate Communications","Advertising","Market Research","Strategic Marketing","Customer service","Telesales","Account Management","Marketing","Sales","Payroll","Recruitment","Training","Human Resource","Accounting","Financial"

$_new_groups | foreach {
    $_group = $(($_).replace(" ",""))
    #New-Item "C:\File_Share\$($_)\" -type directory
    New-SMBShare –Name $_ –Path "C:\File_Share\$($_)\" –FullAccess "contoso\$_group"
    $groups = get-adgroup -filter 'samaccountname -like "grp-share*"'
    $_count = $(Get-Random -Minimum 0 -Maximum 6)
    for ($i=1; $i -le $_count; $i++) {
        $acl = Get-Acl "C:\File_Share\$($_)"
        $permission = "$((get-addomain).name)\$(($groups | get-random).samaccountname)","FullControl","Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule)
        #$acl | Set-Acl "C:\File_Share\$($_)"
        for ($i=1; $i -le 10; $i++) {
            #New-Item "C:\File_Share\$($_)\$($_)_word_doc_$($i).docx" -type file
            #$acl | Set-Acl "C:\File_Share\$($_)\$($_)_word_doc_$($i).docx"
            #New-Item "C:\File_Share\$($_)\$($_)_excel_$($i).xlsx" -type file
            #$acl | Set-Acl "C:\File_Share\$($_)\$($_)_excel_$($i).xlsx"
        }
         
    }
}

New-Service -Name "Generic Service" -BinaryPathName "C:\WINDOWS\System32\svchost.exe -k netsvcs"

get-adgroup -filter 'samaccountname -like "grp-*"' | foreach {
    $_group_name = "grp-contoso-general-$(Get-Random -Minimum 1 -Maximum 300)"
    $_ | Rename-ADObject -NewName $_group_name

}
"grp-fabrikam-general"| foreach { $_count = $(Get-Random -Minimum 1 -Maximum 40)
    for ($i=1; $i -le 10; $i++) {
        $_gn = $(Get-Random -Minimum 1 -Maximum 100)
        New-ADGroup "$($_)-$_gn" -SamAccountName "$($_)-$_gn" -DisplayName "$($_)-$_gn)" -GroupScope Global -GroupCategory Security -Path $_ou
    }
}




$_new_groups | foreach {$gname = $_
    $Manager = get-adgroupmember $gname  | get-random | get-aduser 
    $Manager | Set-ADUser  -department $gname -Title "Manager"
    get-adgroupmember $gname | where samaccountname -ne $manager.samaccountname | get-aduser | set-aduser -manager $($manager.distinguishedname) -department $gname
}

$ceo = get-aduser -filter * -SearchBase "OU=Enabled Users,OU=User Accounts, $($domainDN)" | get-random 
$ceo | Set-ADUser  -department "Executive" -Title "CEO"

1..5 | foreach {
    get-aduser -filter * -SearchBase "OU=Enabled Users,OU=User Accounts, $($domainDN)" | get-random | Set-ADUser  -department "Executive" -Title "President" -manager $ceo.DistinguishedName
}

$ceo = get-aduser -filter * -SearchBase "OU=Enabled Users,OU=User Accounts, $($domainDN)" -Properties title | where Title -eq "CEO"
$execs = get-aduser -filter * -SearchBase "OU=Enabled Users,OU=User Accounts, $($domainDN)" -Properties title | where Title -eq "President"
$execs | foreach{ $_ | set-aduser -Manager $ceo.DistinguishedName}
get-aduser -filter * -SearchBase "OU=Enabled Users,OU=User Accounts, $($domainDN)" -Properties title | where Title -eq "Manager" | foreach{
    $_ | set-aduser -manager ($execs | get-random).distinguishedname
}
