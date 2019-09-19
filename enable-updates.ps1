[CmdltBinding()]
param()

Write-Verbose "Checking installed updates" 

#Creating COM Windows Update object. Com Object only exists in Windows Server 2012 R2 or older
$updateSession = New-Object -ComObject "Microsoft.Update.Session"
$updateSearcher = $updateSession.CreateUpdateSearcher()
Write-Verbose "Starting update search"
#Search for missing important updates 
$searchResults = $updateSearcher.Search("isInstalled=0 and AutoSelectOnWebSites=1")

#Check fi any updates need to be installed
If ($searchResults.Updates.Count -eq 0)
{
    Write-Host 'All Up to Date no Updates Needed'
    exit


}
Write-Verbose "Creating Download Selection"
#create Updates collection class for download
$updatesToDownload = new-object -ComObject "Microsoft.Update.UpdateColl"

forEach ($update in $searchResults.Updates)
{

    #verify if updates requier input or EULA acceptance 
    if ($update.InstallationBehavior.CanRequestUserInput -eq $true  -or $update.EulaAccepted -eq $false)
    {

        Write-Host "Skipping update. Can not be installed unattended"
        Continue
    }
    #add update to the list updates to be dowloaded
    $updatesToDownload.Add($update) | Out-Null







}

#verify updates ready for downloading
If ($updatesToDownload.Count -eq 0)
{


    Write-Host "No updates to download. Exiting script"
    exit

}

#Create download object and start downloading updates
Write-Verbose "Downloading Updates" 
$downloader = $updateSession.CreateUpdateDownloader()
$downloader.Updates = $updatesToDownload
$downloader.Download()

Write-verbose "Download complete."
Write-Verbose "Creating Installation Object"

# create updates to install collection 
$updatesToInstall = New-Object -Comobject "Microsoft.Update.UpdateColl"


#add downloaded updates to install collection
forEach ($update in $searchResults.Updates)
{

    if($update.IsDownloaded -eq $true)
    {

        $updatesToInstall.Add($update) | Out-Null


    }



}

#intiate update installer class and start installing updates
$updateInstaller = $updateSession.CreateUpdateInstaller()
$updateInstaller.Updates = $updatesToInstall

$installResult = $updateInstaller.Install()

$installResult.ResultCode

if ($Results.RebootRequired) { 
    Write-Verbose "Rebooting..." 
    Restart-Computer -Force
} 


