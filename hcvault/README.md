# HashiCorp Vault Module for StrongDM Azure Lab

## Overview

This module creates a single-node HashiCorp Vault development instance that demonstrates StrongDM's integration with external secret management systems. It deploys Vault with Azure Key Vault auto-unseal capabilities and managed identity authentication, showcasing enterprise-grade secret management integration.

## Architecture

The module provisions:
- Ubuntu 20.04 LTS virtual machine (Standard_B2s size)
- Network interface in the private subnet
- HashiCorp Vault installation with development mode configuration
- Azure Key Vault integration for auto-unseal operations
- Managed identity for secure Azure service authentication
- StrongDM integration for secure Vault access

## Features

- **Auto-Unseal**: Uses Azure Key Vault cryptographic keys for automatic unsealing
- **Managed Identity**: System-assigned identity for Azure service authentication
- **Development Mode**: Pre-configured for lab and demonstration scenarios
- **KV Secrets Engine**: Enabled with full permissions on the kv/ path
- **Private Network**: Deployed in private subnet accessible only through StrongDM
- **TLS Configuration**: HTTPS enabled for secure API communication

## Use Cases for Partner Training

1. **External Secret Store Integration**: Demonstrate StrongDM's ability to work with third-party secret management
2. **Dynamic Secret Generation**: Show how Vault can generate temporary credentials for StrongDM targets
3. **Secret Rotation**: Illustrate automated credential rotation workflows
4. **Enterprise Architecture**: Demonstrate how StrongDM fits into complex enterprise secret management
5. **Audit and Compliance**: Show unified auditing across multiple secret management systems

## Configuration

### Basic Usage

```hcl
module "hashicorp_vault" {
  source        = "../hcvault"
  region        = var.region
  rg            = var.rg
  subnet        = var.relay_subnet_id
  tagset        = var.tagset
  name          = var.name
  akvid         = var.key_vault_id
  key_vault_id  = var.key_vault_id
}
```

### Required Variables

- `region`: Azure region for resource deployment
- `rg`: Resource group name where VM resources will be created
- `subnet`: Subnet ID for VM network interface deployment
- `tagset`: Tags to apply to all resources
- `name`: Name prefix for all resources
- `akvid`: Azure Key Vault resource ID for auto-unseal configuration
- `key_vault_id`: Azure Key Vault ID for credential storage

## VM Specifications

- **Operating System**: Ubuntu 20.04 LTS
- **VM Size**: Standard_B2s (2 vCPUs, 4 GB RAM)
- **Storage**: Premium managed disk
- **Network**: Private IP address in relay subnet
- **Authentication**: SSH key-based access

## Vault Configuration

### Development Mode Features
- **Auto-Initialization**: Vault automatically initializes and unseals
- **Root Token**: Development root token for initial access
- **In-Memory Storage**: Data stored in memory (not persistent across reboots)
- **TLS Disabled**: For simplicity in lab environment

### Azure Integration
- **Auto-Unseal**: Uses Azure Key Vault for unsealing operations
- **Managed Identity**: Authenticates to Azure using system-assigned identity
- **Key Vault Access**: "Key Vault Crypto User" role for unseal operations

### Secrets Engines
- **KV v2**: Key-value secrets engine enabled at kv/ path
- **Full Permissions**: Gateway managed identity has full access to kv/ path
- **API Access**: RESTful API for secret operations

## Security Features

1. **Managed Identity Authentication**: No stored credentials for Azure access
2. **Auto-Unseal**: Secure unsealing without manual intervention
3. **Private Network**: No public IP address - accessible only through StrongDM
4. **RBAC Integration**: Role-based access control through Azure RBAC
5. **Audit Logging**: All operations logged for compliance

## Installation Process

The Vault installation is handled by the `vault-provision.tpl` script:

### Phase 1: System Setup
- Install HashiCorp Vault binary
- Configure system users and directories
- Set up systemd service configuration

### Phase 2: Vault Configuration
- Configure auto-unseal with Azure Key Vault
- Set up TLS certificates (if enabled)
- Configure storage backend

### Phase 3: Initialization
- Start Vault service
- Configure secrets engines
- Set up initial authentication methods

## Generated Resources

The module creates:
- Azure Linux Virtual Machine with Vault
- Network Interface with private IP
- SSH key pair for VM access
- Azure role assignments for managed identity
- Vault configuration files and systemd service

## Outputs

- `vm_name`: Name of the created Vault VM
- `private_ip`: Private IP address of the VM
- `vault_url`: Internal URL for Vault API access
- `ssh_private_key_secret`: Key Vault secret name containing SSH private key
- `managed_identity_id`: Principal ID of the VM's managed identity

## Integration with StrongDM

This HashiCorp Vault instance is designed to integrate with StrongDM for:
- Secure API access to Vault endpoints
- Session recording of Vault CLI and API operations
- Integration with StrongDM's secret store capabilities
- Dynamic secret generation for other lab targets
- Audit trail of all secret management operations

## Vault CLI Usage

Once configured in StrongDM, users can access Vault with commands like:

```bash
# Set Vault address (handled by StrongDM session)
export VAULT_ADDR="https://<vault-private-ip>:8200"

# Authenticate using managed identity or token
vault auth -method=azure

# Example operations
vault kv put secret/myapp username=admin password=secret
vault kv get secret/myapp
vault kv list secret/
```

## Important Notes

- ⚠️ **Development Mode**: This is a development instance - data is not persistent
- ⚠️ **Network Access**: Accessible only through StrongDM for security
- ⚠️ **Auto-Unseal**: Requires Azure Key Vault access for automatic unsealing
- ⚠️ **Root Token**: Development root token should be rotated in production scenarios

## Troubleshooting

Common issues and solutions:

1. **Vault Won't Start**:
   - Check Azure Key Vault permissions for managed identity
   - Verify auto-unseal configuration
   - Review Vault service logs

2. **Authentication Issues**:
   - Confirm managed identity role assignments
   - Verify Azure authentication method configuration
   - Check Azure RBAC permissions

3. **Network Connectivity**:
   - Ensure VM is in correct private subnet
   - Verify StrongDM can reach Vault IP
   - Check security group rules

4. **API Access Problems**:
   - Verify Vault service is running
   - Check TLS configuration
   - Ensure proper authentication tokens
