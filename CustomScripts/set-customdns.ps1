param(
    $resourceGroup,
    $vnetName,
    $dc1,
    $dc2

)
$dnsArray=@()
$dc1,$dc2 | ForEach-Object {
    
    $nicConfigurationData = Get-AzNetworkInterface -ResourceId (get-azvm -ResourceGroupName $resourceGroup -Name $PSItem).NetworkProfile.NetworkInterfaces.id
    #$nicConfigurationData.IpConfigurations[0].PrivateIpAddress = "10.0.1.20"
    $nicConfigurationData.IpConfigurations[0].PrivateIpAllocationMethod = "Static"
    Set-AzNetworkInterface -NetworkInterface $nicConfigurationData
    $dnsArray += $nicConfigurationData.IpConfigurations[0].PrivateIpAddress
}
$ErrorActionPreference = 'Stop'
$vnetData = Get-AzVirtualNetwork -ResourceGroupName $resourceGroup -Name $vnetName
$vnetdata.DhcpOptions.DnsServers = $dnsArray
$vnetData | Set-AzVirtualNetwork