# Domain Controller Module for StrongDM Lab

## Overview

This module deploys a Windows Server domain controller in AWS that provides Active Directory infrastructure for the StrongDM lab environment. It establishes a secure foundation for Windows-based authentication, including certificate-based access to Windows targets.

## Architecture

The module provisions:
- A Windows Server EC2 instance configured as a domain controller
- Active Directory Domain Services (AD DS)
- Active Directory Certificate Services (AD CS) with an Enterprise Root CA
- Group Policy Objects (GPOs) for secure access configuration
- Cross-platform support for retrieving StrongDM certificates

## Installation Process

### Full Installation (use_packer_ami = false)

The domain controller setup follows a multi-stage process with automatic restarts:

1. **Computer Rename**: Changes hostname to `dc1` (triggers reboot)
2. **Feature Installation**: Installs ADDS, DNS, and ADCS Windows features
3. **AD DS Configuration**: Creates a new forest and domain (triggers reboot)
4. **Certificate Services**: Installs and configures the Enterprise CA
5. **StrongDM Integration**: Imports the StrongDM RDP CA certificate
6. **User Configuration**: Creates and configures a domain administrator account
7. **Group Policy**: Configures certificate authentication and disables NLA

**Total Time**: ~18-25 minutes

### Optimized Installation (use_packer_ami = true)

When using a Packer-built AMI, the installation is significantly faster:

1. **AD DS Configuration**: Creates a new forest and domain (triggers reboot)
   - ✅ ADDS/DNS features already installed in AMI
   - ✅ Hostname rename skipped (not required for domain functionality)
2. **Certificate Services**: Installs ADCS feature and configures Enterprise CA
3. **StrongDM Integration**: Imports the StrongDM RDP CA certificate
4. **User Configuration**: Creates and configures a domain administrator account
5. **Group Policy**: Configures certificate authentication and disables NLA

**Total Time**: ~11 minutes (**50% faster!**)

Status files are created at each stage to ensure idempotence across restarts.

### Building the Packer AMI

To create the optimized Packer AMI, see the `packer/` directory in the `europa` project:

```bash
cd ~/workspace/europa/packer
packer init windows-dc-base.pkr.hcl
packer build -var-file=variables.pkrvars.hcl windows-dc-base.pkr.hcl
```

The Packer template pre-installs:
- Active Directory Domain Services (ADDS) Windows feature
- DNS Server Windows feature
- PowerShell modules (ADDSDeployment, DnsServer)
- AWS Tools for PowerShell
- Base system configuration (RDP, execution policy, power settings)

**Note**: ADCS is NOT installed in Packer because Windows Server blocks DC promotion if Certificate Services is already installed. ADCS is installed during deployment after DC promotion completes.

## Use Cases for Partner Training

1. **Certificate-Based Authentication**: Demonstrate how StrongDM can leverage AD certificates for Windows access
2. **Domain Account Management**: Show how StrongDM integrates with Active Directory for authentication
3. **Group Policy Control**: Illustrate how StrongDM access policies can complement Windows Group Policy

## Configuration

### Basic Usage

#### Option 1: Vanilla Windows Server (Default - Full Installation)

```hcl
module "dc" {
  source    = "../dc"
  ami       = data.aws_ami.windows.id  # Standard Windows Server 2019 AMI
  tagset    = var.tagset
  name      = var.name
  subnet_id = var.relay_subnet
  sg        = var.private_sg

  # use_packer_ami = false (default)
  # Deployment time: ~18-25 minutes
}
```

#### Option 2: Packer-Built AMI (Optimized - Faster Deployment)

```hcl
module "dc" {
  source         = "../dc"
  ami            = data.aws_ami.packer_dc.id  # Packer-built AMI with ADDS/DNS pre-installed
  use_packer_ami = true                        # Enable optimized installation script
  tagset         = var.tagset
  name           = var.name
  subnet_id      = var.relay_subnet
  sg             = var.private_sg

  # Deployment time: ~11 minutes (50% faster!)
}
```

### Required Variables

- `ami`: Windows Server AMI ID
- `tagset`: Tags to apply to resources
- `name`: Name prefix for all resources and the domain
- `subnet_id`: Subnet ID where the domain controller will be deployed
- `sg`: Security group ID allowing required domain controller traffic

### Optional Variables

- `use_packer_ami` (bool, default: `false`): Set to `true` if using a Packer-built AMI with pre-installed ADDS/DNS features. This enables the optimized installation script that:
  - Skips Windows feature installation (already done in AMI)
  - Skips hostname rename (saves one reboot)
  - Uses optimized service wait times
  - **Reduces deployment time from ~18 min to ~11 min (50% improvement)**
- `domain_users` (set of objects, optional): Additional domain users to create beyond the default domain admin

## Integration with StrongDM

This module creates a domain controller that serves as the foundation for Windows authentication in the StrongDM environment. The dc-target.tf file in the main module demonstrates how to register this domain controller as a StrongDM resource.

The module's outputs provide all necessary information for other modules to configure resources that need to connect to the domain, such as Windows targets.

## Best Practices

For production environments (unlike this demo):
- Use a larger instance type for better performance
- Configure backup and recovery procedures
- Set up a multi-DC architecture across availability zones 
- Implement proper AD site topology
- Use a more complex password policy