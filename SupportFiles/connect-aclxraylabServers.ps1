


param(
  $rg = 'aclxraylab'
)
Function GenerateMenu ([object]$items) {
  $menu = @{}
  $i = 1
  Foreach ($item in $items) {
    $menu.Add($i, $item)
    Write-Host "$($i)) $($item)" -ForegroundColor DarkGray
    $i += 1
        
  }
  return $menu
}

$currentUser = Get-AzContext
if ([string]::IsNullOrEmpty($currentUser)) {
  Login-AzAccount
  $currentUser = Get-AzContext

}

Write-Host "Current subscripton $($currentuser.Subscription.Name)" -ForegroundColor Cyan
Get-AzResourceGroup -Name $rg -ErrorAction SilentlyContinue -ErrorVariable errorData | Out-Null

#verifying existing Resource Group 
if (!([string]::IsNullOrEmpty($errorData))) {
  $title = "ACLXRAY Lab deployment"
  $message = "Unable to find default resource group 'ACLXRAYLAB'.Please select 'NO' to exit scritp, enter correct subscription and re-lauch script`nIf you deployed ACLXRAYLAB to a diffirent resource group, please select 'Yes' name of the resource group below"
  $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes"
  $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No"
  $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
  $resultResourceGroup = $host.ui.PromptForChoice($title, $message, $options, 0) 
  switch ($resultResourceGroup) {
    0 {
      $RG = Read-Host "Enter New Resource Group Name`nPress enter if you want to exit the script"
      if ([string]::IsNullOrEmpty($RG)) {
        Write-Host "Operation canceled.Ending script" 
        Exit
      }

    }
    1 {
      exit
    }

  }
}

$serverMenu = @{}

Write-Host "Please select one of the servers from the menu below" -ForegroundColor DarkGray

$serverMenu = GenerateMenu @("CONTOSODC1", "FABRIKAMDC1", "CONTOSOFS1", "FABRIKAMFS1")

[int]$selection = Read-Host "Type server # and hit enter"

Write-Host "Getting Load Blancers FQDN"

$fqdn = (Get-AzPublicIpAddress -ResourceGroupName $rg).DnsSettings.Fqdn

switch ($selection) {
  1 {
    $PortId = '2400'
    $vmName = 'CONTOSODC1'
    $domain = "contosoad"
    break

  } 
  2 {
    $PortId = '2500'
    $vmName = 'FABRIKAMDC1'
    $domain = "fabrikamad"
    break 
  }
  3 {
    $PortId = '2401'
    $vmName = 'CONTOSOFS1'
    $domain = "contosoad"
    break
  }
  4 {
    $PortId = '2501'
    $vmName = 'FABRIKAMFS1'
    $domain = "fabrikamad"
    break
  }

}

"alternative full address:s:$($vmname)`nfull address:s:$($fqdn):$($PortId)`n`nprompt for credentials:i:1`nadministrative session:i:1`ndomain:s:$($domain)`nusername:s:groot"| Out-File "$($env:TEMP)\$($vmname).rdp" -Force
mstsc "$($env:TEMP)\$($vmname).rdp"