<# Custom Script for Windows #>
Get-NetFirewallProfile  | set-NetFirewallProfile -LogAllowed True -LogBlocked True -LogIgnored True

"Script location: $PSScriptRoot" | Out-File (join-path $env:temp "location.txt") -Force


$currentDomain = Get-ADDomain -Current LocalComputer

$ous = Import-CSV (Join-Path $PSScriptRoot "OUs.csv")
$ous | New-ADOrganizationalUnit -Path $currentDomain.DistinguishedName

$users = Import-CSV (Join-Path $PSScriptRoot "$($currentDomain.NetBIOSName)-Users.csv")
Foreach ($user in $users)
	{
		New-ADUser -GivenName $user.GivenName -Surname $user.Surname  -DisplayName $user.DisplayName -Name $user.Name -SamAccountName $user.SamAccountName -UserPrincipalName "$($user.SamAccountName)@$($currentDomain.NetBIOSName).$($currentDomain.ParentDomain)" -AccountPassword (ConvertTo-SecureString "passw@rd1" -AsPlainText -Force) -PasswordNeverExpires $True -ChangePasswordAtLogon $False -Enabled $True -Path "OU=Company Users,$($currentDomain.DistinguishedName)"
	}

$Cert = New-SelfSignedCertificate -CertstoreLocation Cert:\LocalMachine\My -DnsName $env:COMPUTERNAME
Enable-PSRemoting -SkipNetworkProfileCheck -Force
New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $Cert.Thumbprint –Force
New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -Name "Windows Remote Management (HTTPS-In)" -Profile Any -LocalPort 5986 -Protocol TCP
Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True -LogIgnored True