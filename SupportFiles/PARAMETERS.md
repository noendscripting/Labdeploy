# Labdeploy Deployment Parameters

Documented parameters for the aclxray10.ps file

## -vmsize

### Description

Parameter specicifies size of each VMs in the deployment. Needs a value supported by Azure Compute configuration, to get a list of all supported size name, run followin Az powershell command:

```pwsh
Get-AzVMSize -Location <name of Azure Region where want to deploying this lab> | select Name
```

### Properties

* Type: string
* Mandatory: YES
* Default Value: 'Standard_B2s'

## -region

### Description

Parameter specicifies name of the Azure region for the lab deployment. Need a value supported by Azure Resource Manager, to get list of all possible values, run following Az command:

```pwsh
Get-AzLocation | select Location,DisplayName
```

### Properties

* Type: string
* Mandatory: YES
* Default Value: 'eastus'

## -RG

### Description

Parameter specifies name of the resource group. Can be either existing group or name of a resource group you want to create as part of deployment.

> :warning: **WARNING** If you select existing resource group, all previusly deployed ACLXRAY lab componenets will be overwritten.
### Properties

* Type: string
* Mandatory: YES
* Default Value: NONE - value must be provided at each run

## -shutdownTimeZone

### Description

Parameter specicifies name of the timezone for the shutdown schedule assigned to each VM. Uses standard Winodws OS Time Zone naming conventions. Complete list of all Time Zone Names can be found at [Microsoft Support site](https://support.microsoft.com/en-us/help/973627/microsoft-time-zone-index-values)

### Properties

* Type: string
* Mandatory: YES
* Default Value: 'Eastern Standard Time'

## -shutDownTime

### Description

Parameter specicifies time in 24 hour format, when shutdown schedule excutes VM shutdown

### Properties

* Type: string
* Mandatory: YES
* Default Value: '01:00'

## -vnetname

### Description

Parameter specifies name of the virtual network (VNET). Can be either existing VNET or name of a VNET you want to create as part of deployment.

> :warning: **WARNING** If you select existing VNET name, all ACLXRAYLAB network related items will be reset to original configuration,  i.g if you converted one of the public IP addresses to static.

### Properties

* Type: string
* Mandatory: YES
* Default Value: 'ACLXRAYlabvnet'

## -containerName

### Description

Parameter specifies name of the storage container where DSC and custiom scripts will be uploded. Can be either existing container name or a new one.

### Properties

* Type: string
* Mandatory: YES
* Default value: 'storageartifacts'
