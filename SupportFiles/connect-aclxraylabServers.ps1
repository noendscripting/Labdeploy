param(
    $rg='acxraylab1'
)


$currentUser = Get-AzContext
if ([string]::IsNullOrEmpty($currentUser)) {
  Login-AzAccount
  $currentUser = Get-AzContext

}

Write-Host "Current subscripton $($currentuser.Subscription.Name)"
Get-AzResourceGroup -Name $RG -ErrorAction SilentlyContinue -ErrorVariable errorData | Out-Null

#verifying existing Resource Group 
if ([string]::IsNullOrEmpty($errorData)) {
  $title = "ACLXRAY Lab deployment"
  $message = "Unable to find default resource group 'ACLXRATLAB'.Please select 'NO' to exit scritp, enter correct subscription and re-lauch script`nIf you deployed ACLXRAYLAB to a diffirent resource group, please select 'Yes' name of the resource group below"
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