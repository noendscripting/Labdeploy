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

### Deployment diagram

![Lab Diagram](/SupportFiles/labdiagram.png)

## Deploying lab

### What you need

* Access to Azure Subscriotion with contributor role and ability to create and configure virtual networks
* Following powershell modules [installed](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module?view=powershell-7) on your source system
  * Az
  * PSDesiredStateConfiguration
  * ActiveDirectoryDsc
  * ComputerManagementDsc
  * StorageDsc
* [VSCode editor](https://code.visualstudio.com/)(optional)

### Prepare to deploy

* [Clone repostory](https://www.howtogeek.com/451360/how-to-clone-a-github-repository/) or save repository as a zip file and expand on local disk ![dowload repository content as zip](/SupportFiles/DownloadRepo.PNG) 
* If running deployment for the first time open powershell terminal as administrator and install required modules

### Deploy Lab with default settings

1. Open Powershell terminal or use previusly opened terminal
2. Using powershell command navigate to the root of the directory containing source files
3. In the same terminal run Login-AzAccount and follow steps to log in to Azure  
4. Run ./aclray10.ps1 to deploy the lab with default settings and enter name of Resource Group, to be used for deployment, when prompted.

### Deploy with custom settings


