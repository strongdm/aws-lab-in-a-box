# StrongDM Lab in a Box for AWS

> [!Warning]
> While we will attempt to keep tagged versions "working", there are a lot of improvements being shipped.
> Update with caution :)

## Overview

This repository contains a set of modules that enable the user to deploy a quick lab environment to evaluate StrongDM capabilities. The infrastructure is fully automated using Terraform and can be deployed in your AWS account in minutes.

### Included Resources

- **Network Infrastructure**: VPC, subnets, security groups, NAT and Internet Gateway
- **StrongDM Infrastructure**: Gateway and relay with AWS secrets manager integration
- **Database Targets**:
  - RDS PostgreSQL with credentials in AWS Secrets Manager
  - DocumentDB cluster with MongoDB compatibility
- **Windows Resources**:
  - Windows domain controller
  - Windows server target with certificate authentication
- **Linux Resources**: SSH target using StrongDM's CA for authentication
- **Kubernetes**: EKS Cluster for container workloads
- **AWS Access**: Read-only access to AWS resources via CLI and Console

All resources are properly tagged according to variables set in the module, ensuring consistent resource management and appropriate access roles in StrongDM.

## Architecture

The lab environment creates a secure network architecture with:
- Public subnet for internet-facing components (StrongDM gateway)
- Private subnets for protected resources (databases, servers)
- Security groups configured for least-privilege access
- Proper routing between public and private resources

## Prerequisites

In addition to the usual access credentials for AWS, the modules require an access key to StrongDM with the following privileges:

![StrongDM Permissions](doc/strongdm-permissions.png?raw=true)

```bash
sdm admin tokens add TerraformSecMgmt --permissions secretstore:list,secretstore:create,secretstore:update,secretstore:delete,organization:view_settings,relay:list,relay:create,policy:read,policy:write,datasource:list,datasource:create,datasource:update,datasource:delete,datasource:healthcheck,resourcelock:delete,resourcelock:list,accessrequest:requester,secretengine:create,secretengine:list,secretengine:delete,secretengine:update,managedsecret:list,managedsecret:update,managedsecret:create,managedsecret:read,managedsecret:delete --duration 648000 --type api
```

Export the environment variables:

```bash
export SDM_API_ACCESS_KEY=auth-aaabbbbcccccc
export SDM_API_SECRET_KEY=jksafhlksdhfsahgghdslkhaslghasdlkghlasdkhglkshg
```
or in Powershell:
```powershell
$env:SDM_API_ACCESS_KEY="auth-xxxxxx888x8x88x8x6"
$env:SDM_API_SECRET_KEY="X4fasfasfasfasfasfsafaaqED34ge5343CkQ"
```

> [!NOTE]
> If your control plane is in the UK, or the EU, make sure that the SDM_API_HOST variable is correctly set.
> Gateways and relays *will* use this variable as well to register against the right tenant

```bash
export SDM_API_HOST=api.uk.strongdm.com:443
```
or in Powershell:
```powershell
$env:SDM_API_HOST="api.uk.strongdm.com:443"
```

> [!NOTE]
> The verification of the operating system is done based on the presence of "c:" in the module path. If there is no c:,
> the module will not assume you're using Windows.

Make sure you're logged into sdm with:
```bash
sdm login
```
This is important if you're using the Windows CA target on versions under 2.0, as it will use the local process to pull the Windows CA Certificate. 

> [!Info]
> As of version 2.0 of the lab, this has now been replaced by a new purpose built SDM Resource. Leaving here for historical purposes.
> 

## Configuration Variables

### Network Configuration
- `vpc`: ID of an existing VPC. If null, a new VPC will be created.
- `gateway_subnet`: ID of a public subnet.
- `relay_subnet(-b,-c)`: Private subnets to deploy resources.
- `private_sg`: ID of the security group for private machines (reachable by the relay).
- `public_sg`: ID of the public security group.
- `region`: AWS region where resources will be deployed (default: us-east-2).

> The module will not verify if the right network configuration is set, so make sure to refer to the SDM [Ports Guide](https://www.strongdm.com/docs/admin/deployment/ports-guide/)

### Resource Flags
- `create_linux_target`: Create a Linux target with SSH CA authentication.
- `create_rds_postgresql`: Create an RDS PostgreSQL database.
- `create_docdb`: Create a DocumentDB cluster (MongoDB compatible).
- `create_eks`: Create a Kubernetes cluster.
- `create_domain_controller`: Create a Windows domain controller.
- `create_windows_target`: Create a Windows RDP target.
- `create_aws_ro`: Create a role that can be assumed by the gateway to access AWS.
 
### General Configuration
- `tagset`: Tags to apply to all resources.
- `name`: An arbitrary string that will be added to all resource names.
- `secretkey`: Key for the tag used to filter secrets manager secrets.
- `secretvalue`: Value for the tag used to filter secrets manager secrets.

You can reference the [terraform.tfvars.example](main/terraform.tfvars.example) file in the main module for example configurations.

## Getting Started

Within the main module, do the usual steps:

```bash
cd main
terraform init
terraform plan
terraform apply
``` 

If you're running this in Windows, you may have to set your execution policy accordingly as the script will run local PowerShell commands to retrieve the CA certificate:

```powershell
Set-ExecutionPolicy Bypass
```

## Windows Target Considerations



Setting up a domain controller takes several reboots. This is implemented by a persistent PowerShell script that runs at each reboot and has flow control through creating some "flag files" in C:\ with the "done" extension as each step is completed. You can reference the full PowerShell script [here](dc/install-dc.ps1.tpl).

Note that you cannot deploy the "Windows target" until the domain controller is up and running.

## Training Scenarios

This lab environment supports various training scenarios:

1. **Database Access Management**: Configure secure access to PostgreSQL and DocumentDB databases
2. **Server Access Control**: Manage Windows and Linux server access with certificate authentication
3. **Kubernetes Integration**: Demonstrate K8s cluster access management
4. **Cloud Permissions**: Show controlled AWS resources access through StrongDM

## Troubleshooting

Common issues and their solutions:

1. **Connection Failures**: Verify security groups allow traffic on required ports
2. **Authentication Issues**: Check the SDM API credentials and permissions
3. **Windows Setup Problems**: Examine C:\ for flag files to determine current setup stage

## Contributing

Feel free to submit issues or pull requests to improve the lab environment.
