# HashiCorp Vault Module for StrongDM AWS Lab

## Overview

This module creates a single-node HashiCorp Vault instance that demonstrates StrongDM's integration with external secret management systems. It deploys Vault with AWS KMS auto-unseal capabilities and IAM-based authentication, showcasing enterprise-grade secret management integration in an AWS environment.

## Architecture

The module provisions:
- Ubuntu EC2 instance (t3.small - 2 vCPUs, 2 GB RAM)
- Network interface in the private subnet
- HashiCorp Vault installation with production-ready configuration
- AWS KMS integration for auto-unseal operations
- IAM role and instance profile for AWS service authentication
- StrongDM SSH certificate authentication for secure Vault access
- File-based persistent storage

## Features

- **Auto-Unseal**: Uses AWS KMS cryptographic keys for automatic unsealing
- **IAM Authentication**: EC2 instance uses IAM instance profile for AWS service authentication
- **Production Configuration**: Vault configured with persistent file storage
- **Private Network**: Deployed in private subnet accessible only through StrongDM
- **SSH Certificate Auth**: Secure access using StrongDM's SSH CA
- **No TLS Configuration**: TLS disabled for lab simplicity (enable for production)
- **Automatic Initialization**: Vault automatically initializes with recovery keys

## Use Cases for Training and Demos

1. **External Secret Store Integration**: Demonstrate StrongDM's ability to work with third-party secret management
2. **Dynamic Secret Generation**: Show how Vault can generate temporary credentials for StrongDM targets
3. **Secret Rotation**: Illustrate automated credential rotation workflows
4. **Enterprise Architecture**: Demonstrate how StrongDM fits into complex enterprise secret management
5. **Audit and Compliance**: Show unified auditing across multiple secret management systems
6. **AWS IAM Integration**: Demonstrate AWS-native authentication and authorization patterns

## Configuration

### Basic Usage

```hcl
module "hcvault" {
  source = "../hcvault"
  ami    = data.aws_ami.ubuntu.id
  sshca  = data.sdm_ssh_ca_pubkey.ssh_pubkey_query.public_key
  tagset = var.tagset
  name   = var.name

  subnet_id                  = var.relay_subnet_id
  sg                         = var.private_security_group_id
  relay_instance_profile_arn = aws_iam_instance_profile.relay.arn
  vault_version              = "1.18.4"
}
```

### Required Variables

- `ami`: Ubuntu AMI ID for the EC2 instance
- `sshca`: StrongDM SSH CA public key for certificate-based authentication
- `subnet_id`: Subnet ID for EC2 instance deployment (private subnet)
- `sg`: Security group ID for the Vault instance
- `tagset`: Tags to apply to all resources
- `name`: Name prefix for all resources
- `relay_instance_profile_arn`: ARN of the StrongDM relay instance profile for AWS auth binding

### Optional Variables

- `target_user`: SSH user for the instance (default: "ubuntu")
- `vault_version`: Version of HashiCorp Vault to install (default: "1.18.4")

## EC2 Specifications

- **Operating System**: Ubuntu (latest LTS)
- **Instance Type**: t3.small (2 vCPUs, 2 GB RAM)
- **Storage**: File-based persistent storage at `/opt/vault`
- **Network**: Private IP address in relay/private subnet
- **Authentication**: SSH certificate-based access via StrongDM

## Vault Configuration

### Production-Ready Features
- **Auto-Initialization**: Vault initializes on first boot with recovery shares
- **Recovery Keys**: 3 recovery shares with threshold of 2 (saved to `/home/ubuntu/vault-init.json`)
- **Persistent Storage**: File-based storage for data persistence across reboots
- **UI Enabled**: Vault UI accessible at port 8200
- **HTTP Only**: TLS disabled for lab environment (should be enabled for production)

### AWS Integration
- **Auto-Unseal**: Uses AWS KMS for automatic unsealing operations
- **IAM Instance Profile**: Authenticates to AWS using EC2 instance profile
- **KMS Permissions**: Dedicated IAM policy for Encrypt/Decrypt/DescribeKey operations
- **EC2 Auth Method**: Permissions for EC2-based authentication to Vault

### Storage Configuration
- **Backend**: File storage at `/opt/vault`
- **Persistent**: Data survives instance restarts
- **Permissions**: Owned by the target user (default: ubuntu)

## Security Features

1. **IAM-Based Authentication**: No stored credentials for AWS access
2. **Auto-Unseal**: Secure unsealing without manual key entry
3. **Private Network**: No public IP address - accessible only through StrongDM
4. **SSH Certificate Authentication**: Certificate-based access via StrongDM SSH CA
5. **KMS Key Rotation**: Automatic key rotation enabled on KMS key
6. **Audit Logging**: All operations logged for compliance

## Installation Process

The Vault installation is handled by the `vault-provision.tpl` script:

### Phase 1: System Setup (Lines 1-22)
- Configure StrongDM SSH CA for certificate authentication
- Install required packages (unzip, jq)
- Disable UFW firewall for lab environment
- Configure SSH daemon for certificate authentication

### Phase 2: Vault Installation (Lines 24-88)
- Download HashiCorp Vault binary
- Install Vault to `/usr/bin/vault`
- Create systemd service configuration
- Configure AWS KMS auto-unseal
- Set up file-based storage backend
- Configure HTTP listener on port 8200
- Enable Vault UI

### Phase 3: Initialization (Lines 89-100)
- Start Vault service
- Initialize Vault with recovery shares
- Save recovery keys to `/home/ubuntu/vault-init.json`
- Enable secrets engines and authentication methods

## Generated Resources

The module creates:
- **AWS KMS Key**: For Vault auto-unsealing with key rotation enabled
- **KMS Key Alias**: Named alias for easy identification
- **IAM Role**: For EC2 instance with KMS and EC2 permissions
- **IAM Instance Profile**: Attached to the Vault EC2 instance
- **EC2 Instance**: Running HashiCorp Vault
- **Vault Configuration Files**: In `/etc/vault.d/`
- **Systemd Service**: For automatic Vault service management

## Outputs

- `ip`: Private IP address of the Vault instance
- `instance_id`: EC2 instance ID of the Vault server
- `target_user`: SSH user for the Vault instance
- `tagset`: Tags applied to Vault resources
- `kms_key_id`: KMS key ID used for Vault auto-unsealing
- `vault_url`: Vault server URL (http://PRIVATE_IP:8200)
- `iam_role_arn`: IAM role ARN for the Vault instance

## Integration with StrongDM

This HashiCorp Vault instance integrates with StrongDM for:
- **Secure SSH Access**: Certificate-based SSH access to Vault server via StrongDM
- **Secret Store Integration**: Can be registered as an SDM secret store
- **Session Recording**: All Vault CLI and API operations can be recorded
- **Dynamic Secret Generation**: Generate temporary credentials for other lab targets
- **Audit Trail**: Comprehensive audit log of all secret management operations
- **Relay Authentication**: StrongDM relay can authenticate to Vault using AWS EC2 auth

## Vault Access and Usage

### Accessing Vault via StrongDM

Once registered as an SDM resource, connect via:

```bash
# Connect to Vault server via StrongDM SSH
sdm ssh <vault-resource-name>

# On the Vault server, set environment variables
export VAULT_ADDR="http://127.0.0.1:8200"

# Get the root token from initialization output
ROOT_TOKEN=$(cat ~/vault-init.json | jq -r '.root_token')
vault login $ROOT_TOKEN

# Example operations
vault status
vault secrets list
vault kv put secret/myapp username=admin password=secret
vault kv get secret/myapp
```

### Configuring as StrongDM Secret Store

In the StrongDM admin UI or via Terraform:

```hcl
resource "sdm_secret_store" "vault" {
  vault_token {
    name           = "HashiCorp Vault"
    server_address = module.hcvault.vault_url
    # Configure with Vault token from vault-init.json
  }
}
```

## Recovery Keys

The Vault initialization process generates recovery keys saved to `/home/ubuntu/vault-init.json`:

```json
{
  "recovery_keys_b64": ["key1", "key2", "key3"],
  "recovery_keys_hex": ["hex1", "hex2", "hex3"],
  "recovery_keys_shares": 3,
  "recovery_keys_threshold": 2,
  "root_token": "hvs.xxxxxxxxxxxxxxxx"
}
```

**Important**: These recovery keys are only needed if the KMS key is unavailable. Store them securely for disaster recovery scenarios.

## Important Notes

- ⚠️ **File Storage**: Data is persistent but stored locally - not suitable for HA scenarios
- ⚠️ **TLS Disabled**: HTTP only for lab simplicity - enable TLS for production
- ⚠️ **Private Network**: Accessible only through StrongDM for security
- ⚠️ **KMS Dependency**: Vault requires AWS KMS access for automatic unsealing
- ⚠️ **Root Token**: Saved in clear text in `vault-init.json` - rotate and secure in production
- ⚠️ **Recovery Keys**: Keep recovery keys secure for disaster recovery scenarios

## Troubleshooting

Common issues and solutions:

### 1. Vault Won't Start
**Symptoms**: Vault service fails to start or immediately stops

**Solutions**:
- Check AWS KMS permissions: `aws kms describe-key --key-id <key-id>`
- Verify IAM instance profile is attached: `aws ec2 describe-instances --instance-ids <id>`
- Review Vault logs: `sudo journalctl -u vault -n 100`
- Check systemd service status: `sudo systemctl status vault`

### 2. Auto-Unseal Failures
**Symptoms**: Vault starts but remains sealed

**Solutions**:
- Verify KMS key policy allows the IAM role to use it
- Check IAM role has `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey` permissions
- Review KMS key configuration: Ensure it's not disabled or pending deletion
- Check network connectivity to KMS endpoints

### 3. SSH Authentication Issues
**Symptoms**: Cannot SSH to Vault instance via StrongDM

**Solutions**:
- Verify SSH CA public key is correctly configured
- Check `/etc/ssh/sshd_config.d/100-strongdm.conf` exists
- Confirm principal file exists: `/etc/ssh/sdm_users/ubuntu`
- Restart SSH: `sudo systemctl restart ssh`
- Check SSH daemon logs: `sudo journalctl -u ssh -n 50`

### 4. Network Connectivity
**Symptoms**: Cannot reach Vault API from relay

**Solutions**:
- Ensure instance is in correct private subnet
- Verify security group allows port 8200 from VPC CIDR
- Test connectivity: `curl http://<vault-ip>:8200/v1/sys/health`
- Check route tables and NACLs

### 5. Storage Permissions
**Symptoms**: Vault cannot write to storage

**Solutions**:
- Check directory permissions: `ls -la /opt/vault`
- Ensure target user owns directory: `sudo chown -R ubuntu:ubuntu /opt/vault`
- Verify sufficient disk space: `df -h`

## Maintenance

### Upgrading Vault Version

1. Update the `vault_version` variable
2. Run `terraform apply` to recreate the instance with new version
3. Vault will auto-unseal using KMS
4. Recovery keys remain valid

### Backing Up Vault Data

```bash
# On the Vault server
sudo tar -czf vault-backup-$(date +%Y%m%d).tar.gz /opt/vault

# Download via StrongDM
# Then upload to S3 or another backup location
```

### Rotating KMS Keys

The KMS key has automatic rotation enabled. Manual rotation:

1. Create new KMS key
2. Update Vault configuration to use new key ID
3. Restart Vault service
4. Update Terraform state with new key

## Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│                    AWS Account                       │
│                                                      │
│  ┌────────────────────────────────────────────┐    │
│  │              Private Subnet                 │    │
│  │                                              │    │
│  │  ┌─────────────────────────────────────┐   │    │
│  │  │   Vault EC2 Instance (t3.small)     │   │    │
│  │  │   - HashiCorp Vault 1.18.4          │   │    │
│  │  │   - File Storage: /opt/vault        │   │    │
│  │  │   - Port 8200 (HTTP)                │◄──┼────┼─── StrongDM Relay
│  │  │   - IAM Instance Profile            │   │    │
│  │  │   - SSH Certificate Auth            │   │    │
│  │  └────────────┬────────────────────────┘   │    │
│  │               │                              │    │
│  └───────────────┼──────────────────────────────┘    │
│                  │                                    │
│                  │ KMS API                            │
│                  ▼                                    │
│  ┌─────────────────────────────────────────────┐    │
│  │         AWS KMS (Auto-Unseal)               │    │
│  │   - Customer Managed Key                    │    │
│  │   - Automatic Key Rotation                  │    │
│  └─────────────────────────────────────────────┘    │
│                                                      │
└──────────────────────────────────────────────────────┘
```

## Additional Resources

- [HashiCorp Vault Documentation](https://developer.hashicorp.com/vault/docs)
- [Vault AWS KMS Auto-Unseal](https://developer.hashicorp.com/vault/docs/configuration/seal/awskms)
- [Vault AWS Auth Method](https://developer.hashicorp.com/vault/docs/auth/aws)
- [StrongDM Secret Store Documentation](https://www.strongdm.com/docs/automation/secret-stores)
