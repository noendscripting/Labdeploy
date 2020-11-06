# Labdeploy Deployment Parameters

Documneted paremeters for the aclxray10.ps file

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

> :warning: **WARNING** If you select existing resource group, all previusly deployed ACLXRAY lab componenets will be over written.
### Properties

* Type: string
* Mandatory: YES
* Default Value: 'eastus'

  [string]$RG,
  [string]$shutdownTimeZone = 'Eastern Standard Time',
  [string]$shutDownTime = '01:00',
  [string]$vnetname = 'ACLXRAYlabvnet',
  [string]$containerName = "storageartifacts"