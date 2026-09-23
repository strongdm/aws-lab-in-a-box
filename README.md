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
- `create_adcs`: Create a standalone ADCS/NDES server (see [ADCS/NDES Considerations](#adcsndes-considerations)).
- `adcs_credentials_node`: Which node (`"relay"` or `"gateway"`) carries the ADCS/NDES enrollment credentials (see [ADCS/NDES Enrollment Credentials](#adcsndes-enrollment-credentials-on-the-relaygateway)).
- `create_aws_ro`: Create a role that can be assumed by the gateway to access AWS.
- `create_lab_access`: Create worked examples of roles, Cedar policies and approval workflows for the lab (see [Lab Access](#lab-access)).
- `run_healthchecks`: Ask StrongDM to re-check every registered resource after deployment, so targets do not sit unhealthy until the next scheduled check. Requires the `sdm` CLI on PATH.

### General Configuration
- `tagset`: Tags to apply to all resources.
- `name`: An arbitrary string that will be added to all resource names.
- `secretkey`: Key for the tag used to filter secrets manager secrets.
- `secretvalue`: Value for the tag used to filter secrets manager secrets.
- `lab_approver_account_ids`: StrongDM account IDs added to the lab approver group.
- `dc_ready_timeout`: Seconds to wait for the domain controller before failing the Windows target (default 1800).

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

## Lab Access

Setting `create_lab_access = true` adds worked examples of StrongDM access management, so a
customer can see role-based access, Cedar policies and approval workflows running against
their own lab's targets:

- **Roles** — `<name>-DBA-Team`, `<name>-DevOps-Team`, `<name>-Windows-Admin`,
  `<name>-Cloud-Access`, and `<name>-Full-Access`. Each uses tag-based access rules that
  match the `Name` tags the target modules apply, so targets are picked up as they are
  deployed.
- **Policies** — one requires a justification when the DBA role connects to the
  PostgreSQL or DocumentDB target; the other denies connections to this lab outside
  08:00-18:00 UTC, Monday to Friday. Both are scoped to this lab's `Name` tags, so they
  cannot affect other resources in a shared StrongDM organization. Cedar policies are an
  additional authorization gate on top of the access grants and only take effect when
  policy enforcement is enabled for the organization.
- **Workflows** — a standard workflow that auto-grants one hour of access, and a
  sensitive workflow (databases and the Windows target) that requires approval from the
  `<name>-Approvers` group. The group is created empty, so add members with
  `lab_approver_account_ids` or in the StrongDM UI before demonstrating an approval.

Because the business-hours policy denies connections for every account, keep in mind that
it also applies to you: outside the window, connections to this lab's targets are denied
while `create_lab_access` is enabled.

## Windows Target Considerations



Setting up a domain controller takes several reboots. This is implemented by a persistent PowerShell script that runs at each reboot and has flow control through creating some "flag files" in C:\ with the "done" extension as each step is completed. You can reference the full PowerShell script [here](dc/install-dc.ps1.tpl).

Anything that joins the domain waits for the domain controller rather than racing
it. The install script publishes a completion marker to Parameter Store as its
last act, and `terraform_data.dc_ready` blocks on that marker before the Windows
target, the ADCS server or the AD secret engine is created, for up to
`dc_ready_timeout` seconds. One `terraform apply` therefore deploys the whole
lab. This needs the AWS CLI and the credentials Terraform is already using.

An earlier version of this gate polled the DC's StrongDM health check instead.
That was wrong: the base Windows AMI answers RDP with NLA enabled from first
boot, so the check passed about two minutes after launch, roughly fifteen
minutes before the domain existed. The Windows target was released early, tried
to join a server that was still promoting, and never received the NLA group
policy because the DC had not created it yet.

As per Microsoft [KB5014754](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16) the SID must be added for users or Identity Aliases manually at this point.

## ADCS/NDES Considerations

Setting `create_adcs = true` deploys a standalone Windows server running Active
Directory Certificate Services and NDES, joined to the existing domain controller.
It requires `create_domain_controller = true`: the server joins that domain's
Active Directory, and `terraform plan` fails with an explicit error if the domain
controller is disabled. It joins the domain rather than racing it the same way the
Windows target does, gated behind the same `dc_ready` check (also requiring the
`sdm` CLI and `jq` on PATH), which now covers ADCS-only deployments as well as
`create_windows_target`.

The module derives the server's computer name as `<name>-adcs`, and Windows caps
NetBIOS computer names at 15 characters, so `terraform plan` also fails explicitly
when `var.name` is longer than 10 characters.

Once deployed, the main module exposes two outputs: `ndes_url` (the NDES
enrollment URL) and `adcs_fqdn` (the ADCS server's fully qualified domain name),
both `null` while `create_adcs` is `false`.

The ADCS host is also registered as its own StrongDM RDP resource,
`<name>-adcs-ndes`, covered by the `<name>-Windows-Admin` role when
`create_lab_access = true`, so it has an access path independent of
RDP-hopping through the domain controller. It is registered while the
multi-reboot ADCS install may still be running, so it can sit unhealthy
until the next health check catches up; re-check it directly
with `terraform apply -replace='terraform_data.healthcheck["adcs"]' (with `run_healthchecks = true`; the
address does not exist otherwise)`.

The module stages its PowerShell installers as S3 objects, and those renders
embed the domain administrator password and both service account passwords in
plaintext. Those values therefore live in the object bodies and in Terraform
state. This is an accepted property of an evaluation lab rather than an
oversight: public access to the bucket is blocked and the ADCS instance role is
least-privileged, but any principal in the account holding `s3:GetObject` on
that bucket can read them, and anyone with the state file can read them too.
Treat a deployed lab's AWS account and state file as holding domain credentials,
and destroy the lab when the evaluation finishes.

### ADCS/NDES Enrollment Credentials on the Relay/Gateway

With `create_adcs = true`, the scoped `svc-sdm-relay` service account's
credentials are appended to `/etc/sysconfig/sdm-proxy` on one StrongDM node as
`SDM_ADCS_USER`/`SDM_ADCS_PW`, and that node's `sdm-proxy` service is restarted
to pick them up, so StrongDM can request certificates from the lab's own CA.
`adcs_credentials_node` selects which node: `"relay"` (the default) or
`"gateway"`. Leave it at `"relay"` in this lab's default topology - the DC,
Windows target and ADCS server sit in private subnets that only the relay can
reach. The `"gateway"` setting exists to mirror a customer topology where the
gateway itself reaches NDES; set here, it will not enroll certificates in this
lab's own network. This is wiring only: it does not configure the
`sdm_secret_store` Active Directory CA object that carries the NDES host
setting, which is a separate follow-on task.

Flipping `create_adcs` on an already-deployed lab changes the chosen node's
`user_data`, and both instances set `user_data_replace_on_change = true`, so
Terraform replaces that EC2 instance. It then boots with an already-consumed
StrongDM token and never registers. Taint the matching SDM node alongside the
instance before applying:

```bash
terraform taint 'sdm_node.relay'      # or 'sdm_node.gateway' if adcs_credentials_node = "gateway"
terraform taint 'aws_instance.relay'  # or 'aws_instance.gateway'
terraform apply
```

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
