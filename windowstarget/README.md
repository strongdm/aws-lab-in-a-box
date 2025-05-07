# Windows Target Module for StrongDM Lab

## Overview

This module creates a Windows Server instance in AWS that joins an Active Directory domain and serves as a Windows RDP target for StrongDM access control demonstrations. It enables both password-based and certificate-based authentication through StrongDM.

## Architecture

The module provisions:
- A Windows Server EC2 instance in a private subnet
- Domain join configuration to an existing domain controller
- Configuration of RDP settings to support certificate authentication
- Disabling of Network Level Authentication (NLA) for improved compatibility

## Setup Process

The Windows target setup includes:
1. **Base System Configuration**: Windows Server instance deployment with sufficient storage
2. **Network Configuration**: Setting DNS to use the domain controller
3. **Domain Joining**: Automatic domain join using provided credentials
4. **RDP Configuration**: Disabling NLA to support certificate authentication
5. **Restart**: Automatic restart to complete domain join process

## Use Cases for Partner Training

1. **Windows Access Control**: Demonstrate how StrongDM can manage access to Windows servers
2. **Certificate-Based Authentication**: Show secure RDP access using certificates instead of passwords
3. **Just-In-Time Access**: Illustrate how StrongDM enables temporary, time-limited RDP access
4. **Domain Integration**: Demonstrate integration with Microsoft Active Directory

## Configuration

### Basic Usage

```hcl
module "windowstarget" {
  source    = "../windowstarget"
  ami       = data.aws_ami.windows.id
  tagset    = var.tagset
  name      = var.name
  key_name  = module.dc.key_name
  subnet_id = var.relay_subnet
  sg        = var.private_sg
  dc_ip     = module.dc.dc_ip
  domain_password = module.dc.domain_password
  private_key_pem = module.dc.private_key_pem
}
```

### Required Variables

- `subnet_id`: Subnet ID where the Windows target will be deployed
- `sg`: Security group ID allowing RDP (port 3389) access
- `tagset`: Tags to apply to resources
- `name`: Name prefix for all resources and the domain name
- `ami`: Windows Server AMI ID
- `key_name`: Key pair name for initial password access
- `dc_ip`: IP address of the domain controller
- `domain_password`: Password for the domain admin account to join domain
- `private_key_pem`: Private key in PEM format to decrypt Windows password

## Integration with StrongDM

The main module's `rdp-target.tf` file demonstrates how to register this Windows server with StrongDM using both password and certificate authentication:

```hcl
# Password-based authentication
resource "sdm_resource" "windows-target" {
  rdp {
    name     = "${var.name}-windows-password"
    hostname = module.windowstarget.windowstarget_fqdn
    username = module.windowstarget.windowstarget_username
    password = module.windowstarget.windowstarget_password
    port     = 3389
    tags     = module.windowstarget.thistagset
  }
}

# Certificate-based authentication
resource "sdm_resource" "windows-target-rdp" {
  rdp_cert {
    name     = "${var.name}-windows-ca"
    hostname = module.windowstarget.windowstarget_fqdn
    username = "${var.name}\\Administrator"
    port     = 3389
    tags     = module.windowstarget.thistagset
  }
}
```

This dual approach demonstrates different authentication methods available in StrongDM.

## Best Practices

For production environments (unlike this demo):
- Use custom AMIs with your organizational security baseline
- Implement Windows Update management
- Add additional security mechanisms (antivirus, monitoring)
- Deploy in proper Active Directory OU structure with GPOs
- Use restricted groups and privilege management
- Enable detailed security auditing