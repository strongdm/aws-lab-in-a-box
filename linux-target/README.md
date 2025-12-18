# Linux Target Module for StrongDM Lab

## Overview

This module creates an Ubuntu Linux server in AWS that serves as an SSH target for StrongDM access control demonstrations. It configures SSH Certificate Authority authentication for secure, keyless access through StrongDM.

## Architecture

The module provisions:
- An Ubuntu EC2 instance in a private subnet
- SSH Certificate Authority (CA) configuration for secure authentication
- Script-based configuration via user data for automated setup
- Security group rules allowing SSH access from the private network

## Setup Process

The Linux target setup includes:
1. **Base System Configuration**: Ubuntu instance deployment with security updates
2. **SSH Configuration**: Configuring SSH to trust the StrongDM CA
3. **User Authorization**: Configuring SSH certificate principals
   - **Domain-joined machines**: Uses `AuthorizedPrincipalsCommand` to dynamically allow all domain users
   - **Standalone machines**: Uses `AuthorizedPrincipalsFile` with per-user principal files
4. **Security Hardening**: Disabling password authentication and firewall setup

### SSH Certificate Authentication

This module configures SSH certificate authentication using StrongDM's SSH CA. The principal configuration differs based on whether the machine is domain-joined:

#### Domain-Joined Machines (Active Directory)

When `domain_name` is provided, the module:
- Joins the machine to the Active Directory domain
- Creates an `AuthorizedPrincipalsCommand` script at `/usr/local/bin/sdm-principals.sh`
- Configures SSH to dynamically return the "strongdm" principal for any user
- **Benefit**: All domain users can authenticate without creating individual principal files

The command-based approach eliminates the need to manually create `/etc/ssh/sdm_users/<username>` files for each domain user.

#### Standalone Machines (No Domain)

For non-domain-joined machines:
- Creates `/etc/ssh/sdm_users/<target_user>` containing "strongdm" principal
- Configures SSH with `AuthorizedPrincipalsFile /etc/ssh/sdm_users/%u`
- Only the specified `target_user` can authenticate via SSH certificates

## Use Cases for Partner Training

1. **Secure Shell Access**: Demonstrate how StrongDM provides secure SSH access without exposing credentials
2. **Certificate-Based Authentication**: Show the benefits of SSH certificates over traditional key pairs
3. **Just-In-Time Access**: Illustrate how StrongDM enables temporary, time-limited SSH access to servers
4. **Access Auditing**: Monitor and audit all SSH sessions through StrongDM's logging capabilities

## Configuration

### Basic Usage

```hcl
module "linux-target" {
  source      = "../linux-target"
  target_user = "ubuntu"
  ami         = data.aws_ami.ubuntu.id
  sshca       = data.sdm_ssh_ca_pubkey.ssh_pubkey_query.public_key
  tagset      = var.tagset
  name        = var.name
  subnet_id   = var.relay_subnet
  sg          = var.private_sg
}
```

### Required Variables

- `subnet_id`: Subnet ID where the Linux target will be deployed
- `sg`: Security group ID to associate with the instance
- `tagset`: Tags to apply to all resources
- `name`: Name prefix for all resources
- `sshca`: StrongDM SSH CA certificate public key
- `ami`: Ubuntu AMI ID to use for the instance

### Optional Variables

- `target_user`: Username for SSH access (default: "ubuntu")

## Integration with StrongDM

The main module's `linux-target.tf` file demonstrates how to register this Linux server with StrongDM:

```hcl
resource "sdm_resource" "ssh-ca-target" {
  ssh_cert {
    name     = "${var.name}-ssh-ca-target"
    hostname = module.linux-target.target_hostname
    username = module.linux-target.target_username
    port     = 22
    tags     = module.linux-target.thistagset
  }
}
```

This module outputs the hostname, username, and tags needed to create an SSH resource in StrongDM.

## Best Practices

For production environments (unlike this demo):
- Use custom AMIs with your organizational security baseline
- Implement additional monitoring and logging
- Consider using Systems Manager for additional management capabilities
- Deploy in a private subnet with proper network access controls
- Implement host-based firewalls and intrusion detection