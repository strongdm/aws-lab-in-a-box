#--------------------------------------------------------------
# PostgreSQL Target Configuration
#
# This file creates an Amazon RDS PostgreSQL instance and registers it with
# StrongDM, demonstrating secure database access management with credential
# storage in AWS Secrets Manager. The PostgreSQL target shows how StrongDM
# can provide temporary, just-in-time access to databases without exposing
# permanent credentials to end users.
#
# Components:
# - Amazon RDS PostgreSQL instance in a private subnet
# - AWS Secrets Manager integration for credential management
# - StrongDM resource registration with dynamic credential resolution
#--------------------------------------------------------------

# Create the PostgreSQL RDS instance using the rds module
module "psql-target" {
  source = "../rds"                                   # Reference to the RDS module
  count  = var.create_rds_postgresql == false ? 0 : 1 # Conditionally create based on feature flag
  subnet_id = [coalesce(var.relay_subnet, one(module.network[*].relay_subnet)),
    coalesce(var.relay_subnet-b, one(module.network[*].relay_subnet-b)),
  coalesce(var.relay_subnet-c, one(module.network[*].relay_subnet-c))] # Multi-AZ subnets
  tagset = var.tagset                                                  # Tags for resource identification
  name   = var.name                                                    # Name prefix for resources
  sg     = coalesce(var.public_sg, module.network[0].private_sg)       # Security group

}

# Register the PostgreSQL instance as a database resource in StrongDM
# with credentials referenced from AWS Secrets Manager
resource "sdm_resource" "rds-psql-target" {
  count = var.create_rds_postgresql == false ? 0 : 1
  postgres {
    database = one(module.psql-target[*].db_name)         # Database name on the instance
    name     = "${var.name}-postgresql-target"            # Resource name in StrongDM
    hostname = one(module.psql-target[*].target_hostname) # RDS endpoint address
    port     = one(module.psql-target[*].target_port)     # PostgreSQL port (typically 5432)

    # Use AWS Secrets Manager integration for secure credential management
    username        = "${one(module.psql-target[*].secret_arn)}?key=username" # Username from Secrets Manager
    password        = "${one(module.psql-target[*].secret_arn)}?key=password" # Password from Secrets Manager
    secret_store_id = sdm_secret_store.awssecretsmanager.id                   # Reference to the StrongDM secret store

    tags = one(module.psql-target[*].thistagset) # Tags for access control
  }
}