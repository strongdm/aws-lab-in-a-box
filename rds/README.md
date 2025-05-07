# RDS PostgreSQL Module for StrongDM Lab

## Overview

This module creates an Amazon RDS PostgreSQL instance that serves as a database target for StrongDM access control demonstrations. It deploys a fully managed PostgreSQL database with secure credential management through AWS Secrets Manager.

## Architecture

The module provisions:
- A PostgreSQL database instance (db.t3.micro) in a private subnet
- Database subnet group spanning multiple availability zones
- Secure credential management with AWS Secrets Manager integration
- Default database named "pagila" (sample DVD rental database schema)

## Features

- **Secure Credentials**: Uses AWS managed master user password
- **Multi-AZ Configuration**: Database subnet group spans multiple availability zones
- **Modern PostgreSQL**: Uses PostgreSQL version 16.3
- **Simplified Administration**: Skip final snapshots for lab environment
- **Proper Tagging**: Consistent tagging for resource organization

## Use Cases for Partner Training

1. **Database Access Control**: Demonstrate how StrongDM can manage access to PostgreSQL databases
2. **Just-In-Time Database Credentials**: Show temporary database credential issuance while permanent credentials remain secured
3. **Database Activity Monitoring**: Track and audit SQL queries through StrongDM's logging capabilities
4. **Secrets Management Integration**: Illustrate the integration between StrongDM and AWS Secrets Manager

## Configuration

### Basic Usage

```hcl
module "psql-target" {
  source    = "../rds"
  subnet_id = [subnet-1, subnet-2, subnet-3]
  tagset    = var.tagset
  name      = var.name
  sg        = var.private_sg
}
```

### Required Variables

- `subnet_id`: List of subnet IDs for the database subnet group
- `tagset`: Tags to apply to all resources
- `name`: Name prefix for all resources
- `sg`: Security group ID allowing PostgreSQL (port 5432) access

### Optional Variables

- `db_name`: Name for the PostgreSQL database (default: "pagila")

## Integration with StrongDM

The main module's `psql-target.tf` file demonstrates how to register this PostgreSQL database with StrongDM:

```hcl
resource "sdm_resource" "rds-psql-target" {
  postgres {
    database        = module.psql-target.db_name
    name            = "${var.name}-postgresql-target"
    hostname        = module.psql-target.target_hostname
    port            = module.psql-target.target_port
    username        = "${module.psql-target.secret_arn}?key=username"
    password        = "${module.psql-target.secret_arn}?key=password"
    secret_store_id = sdm_secret_store.awssecretsmanager.id
    tags            = module.psql-target.thistagset
  }
}
```

This configuration leverages AWS Secrets Manager integration with StrongDM, allowing secure access to the database without exposing credentials.

## Best Practices

For production environments (unlike this demo):
- Enable Multi-AZ deployment for high availability
- Use appropriately sized instance types based on workload
- Configure automated backups with longer retention periods
- Implement parameter groups with hardened security settings
- Configure enhanced monitoring and Performance Insights
- Use encryption in transit (SSL/TLS) for all connections