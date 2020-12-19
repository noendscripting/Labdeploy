"OU=Groups,DC=eu,DC=contosoad,DC=com","OU=User Accounts,DC=eu,DC=contosoad,DC=com" | ForEach-Object {
    Remove-ADOrganizationalUnit -Identity $PsItem -Recursive
    
    }
    
    
    
    "C:\Windows\SYSVOL\domain\scripts\*", "C:\Program Files\WindowsPowerShell\Modules\DSInternals\*" | ForEach-Object {
    
    Remove-Item -Path $PSItem -Recurse -Force -Verbose
    
    }