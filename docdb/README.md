# DocumentDB Module for StrongDM Lab

## Overview

This module creates an Amazon DocumentDB cluster that serves as a MongoDB-compatible database target for StrongDM access control demonstrations. DocumentDB provides a fully managed document database service that's compatible with MongoDB workloads.

## Architecture

The module provisions:
- A DocumentDB cluster (control plane and storage)
- One or more DocumentDB instances (compute)
- A subnet group spanning multiple availability zones
- Secure password management

## Use Cases for Partner Training

1. **MongoDB Access Control**: Demonstrate how StrongDM can manage access to MongoDB-compatible databases
2. **Temporary Database Credentials**: Show how StrongDM enables temporary credential issuance while the underlying credentials remain secure
3. **Database Activity Monitoring**: Track and audit all access to the DocumentDB instance through StrongDM

## Configuration

### Basic Usage

```hcl
module "docdb" {
  source    = "../docdb"
  subnet_id = [subnet-1, subnet-2, subnet-3]
  tagset    = var.tagset
  name      = var.name
  sg        = security-group-id
}
```

### Required Variables

- `subnet_id`: List of subnet IDs for deployment (multi-AZ)
- `sg`: Security group ID allowing port 27017 traffic
- `tagset`: Tags to apply to resources
- `name`: Name prefix for all resources

### Optional Variables

- `username`: Admin username (default: "docdbadmin")
- `password`: Admin password (default: auto-generated)
- `instance_class`: Instance size (default: "db.t3.medium")
- `replica_instance_count`: Number of instances (default: 1)

## Integration with StrongDM

This module exports all necessary information for registering with StrongDM:
- Endpoints for connecting
- Credentials for authentication
- Port information (27017)

The main module's `docdb-target.tf` file demonstrates how to create a StrongDM resource using this module's outputs.

## Best Practices

For production deployments (unlike this demo):
- Use at least 3 instances across AZs for high availability
- Use instance types appropriate for your workload (r5 family for memory-intensive)
- Enable encryption in transit
- Set a more robust backup retention policy