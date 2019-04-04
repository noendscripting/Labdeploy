
Write-Verbose "Checking installed updates" 

#Creating COM Windows Update object. Com Object only exists in Windows Server 2012 R2 or older
$UpdateSession = New-Object -ComObject "Microsoft.Update.Session"
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

#Query History of updates for the last 40 days 
If (($UpdateSearcher.QueryHistory(0,1)| Select-Object Date).Date -le (Get-Date).Add(-40))
{
    #If no updates were installed in the last 40 days create a loist of availble updates
    Write-Verbose "Creating Download Selection" 
    $SearchResults = $UpdateSearcher.Search("IsInstalled=0 and IsHidden=0")
    #Filter updates to category system and security
    $availabaleUpdates = $SearchResults.RootCategories.Item(4).Updates

    #Create list for for download
    $DownloadCollection = New-Object -com "Microsoft.Update.UpdateColl"
    ForEach($update in $availabaleUpdates )
    {
        $DownloadCollection.Add($update)
    }
    #Download Updates
    Write-Verbose "Downloading Updates" 
    $Downloader = $UpdateSession.CreateUpdateDownloader() 
    $Downloader.Updates = $DownloadCollection 
    $Downloader.Download() 
    Write-verbose "Download complete."
    Write-Verbose "Creating Installation Object"
    #Start Installation process
    $InstallCollection = New-Object -com "Microsoft.Update.UpdateColl" 
    ForEach($update in $availabaleUpdates )
    {
        if($update.IsDownloaded)
        {
            $InstallCollection.Add($update) | Out-Null 
        }

    }
    $Installer = $UpdateSession.CreateUpdateInstaller() 
    $Installer.Updates = $InstallCollection 
    #Get reuslts and process reboot
    $Results = $Installer.Install()

    if ($Results.RebootRequired) { 
            Write-Verbose "Rebooting..." 
            Restart-Computer
        } 
        

}