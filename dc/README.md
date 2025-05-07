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

The domain controller setup follows a multi-stage process with automatic restarts:

1. **Initial Setup**: Configures hostname and installs required Windows features
2. **AD DS Configuration**: Creates a new forest and domain
3. **Certificate Services**: Installs and configures the Enterprise CA
4. **StrongDM Integration**: Imports the StrongDM RDP CA certificate
5. **User Configuration**: Creates and configures a domain administrator account
6. **Group Policy**: Configures certificate authentication and disables NLA

Status files are created at each stage to ensure idempotence across restarts.

## Use Cases for Partner Training

1. **Certificate-Based Authentication**: Demonstrate how StrongDM can leverage AD certificates for Windows access
2. **Domain Account Management**: Show how StrongDM integrates with Active Directory for authentication
3. **Group Policy Control**: Illustrate how StrongDM access policies can complement Windows Group Policy

## Configuration

### Basic Usage

```hcl
module "dc" {
  source    = "../dc"
  ami       = data.aws_ami.windows.id
  tagset    = var.tagset
  name      = var.name
  subnet_id = var.relay_subnet
  sg        = var.private_sg
}
```

### Required Variables

- `ami`: Windows Server AMI ID
- `tagset`: Tags to apply to resources
- `name`: Name prefix for all resources and the domain
- `subnet_id`: Subnet ID where the domain controller will be deployed
- `sg`: Security group ID allowing required domain controller traffic

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