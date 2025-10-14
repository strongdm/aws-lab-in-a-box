#--------------------------------------------------------------
# Main Variables
#
# This file defines all variables needed to configure the AWS Lab-in-a-Box
# environment. Configuration is primarily done through feature flags that
# enable/disable specific resource types, along with network configuration 
# options and general settings.
#--------------------------------------------------------------

#---------- Network Configuration ----------#

variable "vpc" {
  description = "Use an existing VPC. If nil a new VPC will be created"
  type        = string
  default     = null
}

variable "gateway_subnet" {
  description = "Use an existing public subnet. If nil a new subnet will be created"
  type        = string
  default     = null
}

variable "relay_subnet" {
  description = "Use an existing private subnet. If nil a new subnet will be created"
  type        = string
  default     = null
}

variable "relay_subnet-b" {
  description = "Existing private alternative subnet. Will be required if a relay_subnet is specified and ignored if relay_subnet is not specified"
  type        = string
  default     = null
}

variable "relay_subnet-c" {
  description = "Existing private alternative subnet. Will be required if a relay_subnet is specified and ignored if relay_subnet is not specified"
  type        = string
  default     = null
}

variable "private_sg" {
  description = "Use an existing security for the private subnet. If nil a new security group will be created"
  type        = string
  default     = null
}

variable "public_sg" {
  description = "Use an existing security for the public subnet. If nil a new security group will be created"
  type        = string
  default     = null
}

#---------- Resource Feature Flags ----------#
# Set these to true to enable specific resource types in the deployment

variable "create_eks" {
  description = "Flag to create an Elastic Kubernetes Service"
  type        = bool
  default     = false
}

variable "create_rds_postgresql" {
  description = "Flag to create an RDS PostgreSQL instance"
  type        = bool
  default     = false
}

variable "create_docdb" {
  description = "Flag to create an Amazon DocumentDB instance"
  type        = bool
  default     = false
}

variable "create_domain_controller" {
  description = "Flag to create a domain controller"
  type        = bool
  default     = false
}

variable "create_windows_target" {
  description = "Flag to create a Windows target (VM, instance, etc.)"
  type        = bool
  default     = false
}

variable "create_linux_target" {
  description = "Flag to create a Linux target (VM, instance, etc.)"
  type        = bool
  default     = false
}

#---------- Metadata Configuration ----------#

variable "tagset" {
  description = "Set of Tags to apply to StrongDM resources and AWS infrastructure"
  type        = map(string)
}

variable "name" {
  description = "Arbitrary string to add to resources for identification"
  type        = string
}

#---------- Secrets Configuration ----------#

variable "secretkey" {
  description = "Key for the tag used to filter secrets manager secrets"
  type        = string
}

variable "secretvalue" {
  description = "Value for the tag used to filter secrets manager secrets"
  type        = string
}

#---------- AWS Access Configuration ----------#

variable "create_aws_ro" {
  description = "Create an access profile for StrongDM users in AWS with ReadOnly S3 Permissions"
  type        = bool
  default     = false
}

variable "create_s3_rw" {
  description = "Create an access profile for StrongDM users in AWS with Full S3 Permissions"
  type        = bool
  default     = false
}

#---------- AWS Region Configuration ----------#

variable "region" {
  description = "AWS region where resources will be created"
  type        = string
  default     = "us-east-2" // Default region if none specified
}

#---------- Secrets Management Configuration ----------#
variable "domain_users" {
  description = "Set of map of users to be created in the Directory"
  type = set(object({
    SamAccountName = string
    GivenName      = string
    Surname        = string
    tags           = map(string)
  }))
  default = null
}

variable "create_managedsecrets" {
  description = "Create an access profile for StrongDM users in AWS with Full S3 Permissions"
  type        = bool
  default     = false
}