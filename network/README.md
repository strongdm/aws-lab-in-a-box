# Network Module for StrongDM Lab

## Overview

This module establishes the foundational network infrastructure for the StrongDM lab environment in AWS. It creates a secure, isolated network environment with properly segmented public and private resources following AWS best practices.

## Architecture

![Network Architecture](../doc/network-architecture.png)

The network consists of:

- **VPC**: A dedicated virtual network with CIDR block 10.0.0.0/16
- **Public Subnet**: Houses internet-facing components like the StrongDM Gateway
- **Private Subnets**: Distributed across all available AZs for high availability of protected resources
- **Internet Gateway**: Provides internet access to public subnet resources
- **NAT Gateway**: Enables private subnet resources to access the internet while remaining isolated
- **Security Groups**: Enforces access control between resources with least-privilege permissions

## Resource Deployment

Resources are deployed into specific subnets based on their security requirements:

| Resource Type | Subnet Type | Justification |
|---------------|------------|---------------|
| StrongDM Gateway | Public | Requires inbound connections from users |
| StrongDM Relay | Private | Only needs outbound access to targets |
| Databases (PostgreSQL, DocumentDB) | Private | Protected resources not directly internet accessible |
| Windows/Linux Targets | Private | Protected resources accessed via StrongDM |

## Security Group Rules

The module dynamically creates security group rules based on which resources are enabled:

- PostgreSQL (5432) - When `create_rds_postgresql = true`
- DocumentDB (27017) - When `create_docdb = true` 
- Windows/RDP (3389) - When `create_windows_target = true`
- SSH (22) - When `create_linux_target = true`
- HTTPS (443) - When `create_eks = true`

Additional Windows domain-specific ports are opened when domain controllers are deployed.

## Usage in Partner Training

This network setup demonstrates important security principles:

1. **Network Segmentation**: Separating public-facing components from private data
2. **Least-Privilege Access**: Only necessary ports opened for each resource type
3. **High Availability**: Resources distributed across multiple availability zones
4. **Defense-in-Depth**: Multiple security layers protecting sensitive resources

## Integration with Other Modules

This module outputs subnet IDs, security group IDs, and VPC information that other modules reference when creating their resources, ensuring consistent networking configuration throughout the lab environment.