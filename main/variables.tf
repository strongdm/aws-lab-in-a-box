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

variable "create_eks" {
  description = "Flag to create an Azure Kubernetes Service (AKS)"
  type        = bool
  default     = false
}

variable "create_rds_postgresql" {
  description = "Flag to create an RDS PostgreSQL instance"
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

variable "tagset" {
  description = "Set of Tags to apply to StrongDM resources"
  type        = map(string)
}

variable "name" {
  description = "Arbitrary string to add to resources"
  type        = string
}

variable "secretkey" {
  description = "Key for the tag used to filter secrets manager secrets"
  type        = string
}

variable "secretvalue" {
  description = "Value for the tag used to filter secrets manager secrets"
  type        = string
}

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