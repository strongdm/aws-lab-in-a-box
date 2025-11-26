#--------------------------------------------------------------
# RDS PostgreSQL Module for StrongDM Integration
#
# This module creates an Amazon RDS PostgreSQL instance that serves as a 
# database target for StrongDM access control demonstrations. It configures 
# a PostgreSQL database with AWS Secrets Manager integration for secure 
# credential management.
#
# Components:
# - PostgreSQL RDS instance in a private subnet
# - Database subnet group for multi-AZ deployment
# - AWS Secrets Manager integration for credential management
# - Security group rules allowing PostgreSQL access
#--------------------------------------------------------------

# Create a PostgreSQL database instance with modern version and secure configuration
resource "aws_db_instance" "rds_target" {
  instance_class              = "db.t3.micro"                       # Small instance suitable for demo purposes
  identifier                  = "${var.name}-postgres-db"           # Unique identifier for the RDS instance
  allocated_storage           = 5                                   # 5GB storage allocation is sufficient for demos
  engine                      = "postgres"                          # Use PostgreSQL database engine
  engine_version              = "16.3"                              # Use recent PostgreSQL version
  manage_master_user_password = true                                # AWS will generate and manage the master password in Secrets Manager
  multi_az                    = false                               # Single AZ deployment for lab/demo (use true for production)
  username                    = "dba"                               # Master username for database administration
  vpc_security_group_ids      = [var.sg]                            # Security group allowing PostgreSQL access
  db_name                     = var.db_name                         # Initial database name from variables
  db_subnet_group_name        = aws_db_subnet_group.rds_target.name # Use the subnet group defined below
  skip_final_snapshot         = true                                # Skip final snapshot for easier cleanup in lab environments
  tags                        = local.thistagset                    # Apply consistent tagging
}

# Create a database subnet group that spans multiple availability zones
resource "aws_db_subnet_group" "rds_target" {
  name       = "${var.name}-rds-subnet-group" # Subnet group name with unique prefix
  subnet_ids = var.subnet_id                  # List of subnet IDs from variables

  tags = local.thistagset # Apply consistent tagging
}

# Define a standardized tag set that includes database-specific information
locals {
  thistagset = merge(var.tagset, {
    network = "Private" # Indicates this is a private network resource
    class   = "target"  # Identifies this as a StrongDM target resource
    }
  )
}