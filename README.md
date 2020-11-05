# Labdeploy

In this repository you will find files nesssary for deploying ACLXray Lab.

## What will be deployed to Azure IaaS

The deployment will create:

* VNET
* 2 Subnets
* 2 Network Security Groups
* Storage Account
* 6 VM
* Shutdown schedule for each VM
* Public IP addreses for all VMs
* Two forests one single domain and one suibdomain
* File server attached to each domain
* Users in each forest
* Randomly generated groups with random memberships
* Random ACLs on OUs and files  
* Four accounts with SIM history entries

> **WARNING**: Because all groups and ACLs are created randomly, if you delete and re-deploy lab you will have diffirent settings. SupportFiles folder has two scripts that can help with creating disk snapshots of each VM and then creating a new lab VMs from snapshot if you want to roll back changes. Scripts are provided as is

### Deployment diagram

![Lab Diagram](/SupportFiles/labdiagram.png)

## Deploying lab

### What you need

* Access to Azure Subscriotion with contributor role and ability to create and configure virtual networks
* Following powershell modules [installed](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module?view=powershell-7) on your source system
  * Az
  * PSDscResources
  * ActiveDirectoryDsc
  * ComputerManagementDsc
  * StorageDsc
* [VSCode editor](https://code.visualstudio.com/)(optional)

### Prepare to deploy

* (optional step for developers) [Clone repostory](https://www.howtogeek.com/451360/how-to-clone-a-github-repository/) or save repository as a zip file and expand on local disk ![dowload repository content as zip](/SupportFiles/DownloadRepo.PNG)
* Unzip installation files into a local directory
* If running deployment for the first time open powershell terminal as administrator and install required modules

### Deploy Lab with default settings

1. Open Powershell terminal or use previusly opened terminal
2. Using powershell command navigate to the root of the directory containing source files
3. In the same terminal run Login-AzAccount and follow steps to log in to Azure  
4. Run ./aclray10.ps1 to deploy the lab with default settings and enter name of Resource Group, to be used for deployment, when prompted.

### Deploy with custom settings

Detailed ifomation about parameters can be  found in the parameters readme file
You customize following settings in the lab:

* VM Size (default 'Standard_B2s')
* Region  (default 'eastus')
* Shutodown Time Zone (default 'Eastern Standard Time')
* Shutdown Time (deafult '01:00' 24 hour time)
* Virtual Netowrk Name (default 'ACLXRAYlabvnet')
* Container Name (default 'storageartifacts')

#### Example

In this example we will deploy ACLXRAY Lab into aletrnative region with aleternative Shutdown Time zone and alertnative virtual network name.

>      ./aclzray.ps1 -RG myACLXRAYLAB -region westus -shutdownTimeZone 'Pacific Standard Time' -vnetname VNET02
