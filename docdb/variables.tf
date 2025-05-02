# Variables for DocumentDB module
#
# This file defines the input variables for the DocumentDB module, which is used to create
# a MongoDB-compatible database service in AWS. These variables control aspects such as:
# - Network configuration (subnets, security groups)
# - Instance type and count
# - Database credentials
# - Backup policies
# - Resource naming and tagging

variable "subnet_id" {
  description = "Subnet id list in which to deploy the DocumentDB cluster"
  type        = list(string)
  default     = null
}

variable "sg" {
  description = "Security group in which to deploy the DocumentDB cluster"
  type        = string
  default     = null
}

variable "tagset" {
  description = "Set of Tags to apply to StrongDM resources"
  type        = map(string)
}

variable "name" {
  description = "Arbitrary string to add to resources"
  type        = string
}

variable "username" {
  description = "Master username for DocumentDB"
  type        = string
  default     = "docdbadmin"
}

variable "password" {
  description = "Master password for DocumentDB. If null, a random password will be generated"
  type        = string
  sensitive   = true
  default     = null
}

variable "instance_class" {
  description = "Instance class for DocumentDB instances (determines CPU, memory, etc.)"
  type        = string
  default     = "db.t3.medium"  # t3.medium is suitable for training but not production
}

variable "db_name" {
  description = "Arbitrary database name for initial database"
  type        = string
  default     = "docdb"
}

variable "backup_retention_period" {
  description = "The number of days to retain automated DocumentDB backups"
  type        = number
  default     = 1  # Minimum value for lab/training environments
}

variable "preferred_backup_window" {
  description = "The daily time range during which automated backups are created (HH:MM-HH:MM)"
  type        = string
  default     = "07:00-09:00"  # Early morning backup window
}

variable "replica_instance_count" {
  description = "Number of instances to create in the DocumentDB cluster"
  type        = number
  default     = 1  # Single instance for training; use 2+ for HA in production
}

locals {
  thistagset = merge(var.tagset, {
    network = "Private"
    class   = "target"
    Name    = "sdm-${var.name}-documentdb"
  })
}