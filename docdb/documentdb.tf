// filepath: /Users/stokvis/dev/sdm/aws-lab-in-a-box/documentdb/documentdb.tf
#--------------------------------------------------------------
# AWS DocumentDB Module
#
# This module deploys an Amazon DocumentDB cluster with MongoDB compatibility,
# which serves as a target for StrongDM to manage access to.
#
# The module creates:
# - A DocumentDB subnet group using provided subnets
# - A primary DocumentDB cluster
# - One or more DocumentDB instances in the cluster
#--------------------------------------------------------------

# Create a subnet group for the DocumentDB cluster from provided subnets
resource "aws_docdb_subnet_group" "docdb_subnet_group" {
  name       = "${var.name}-docdb-subnet-group"
  subnet_ids = var.subnet_id

  tags = local.thistagset
}

# DocumentDB Cluster - Contains the storage and metadata for the database
resource "aws_docdb_cluster" "docdb_cluster" {
  cluster_identifier      = "${var.name}-docdb-cluster"
  engine                  = "docdb"                     # DocumentDB uses the docdb engine type
  master_username         = var.username                # Admin username for the cluster
  master_password         = local.actual_password       # Admin password (auto-generated if not provided)
  backup_retention_period = var.backup_retention_period # How many days to retain backups
  preferred_backup_window = var.preferred_backup_window # When to perform backups
  skip_final_snapshot     = true                        # Skip final snapshot on deletion for lab env
  db_subnet_group_name    = aws_docdb_subnet_group.docdb_subnet_group.name
  vpc_security_group_ids  = [var.sg] # Security group to allow access
  storage_encrypted       = true     # Enable storage encryption

  tags = local.thistagset
}

# DocumentDB Instances - The actual database instances that run in the cluster
# Creates the specified number of instances based on replica_instance_count
resource "aws_docdb_cluster_instance" "docdb_instances" {
  count              = var.replica_instance_count
  identifier         = "${var.name}-docdb-instance-${count.index}"
  cluster_identifier = aws_docdb_cluster.docdb_cluster.id
  instance_class     = var.instance_class # Instance size/performance tier

  tags = local.thistagset
}