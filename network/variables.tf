variable "vpc" {
  description = "Use an existing VPC. If nil a new VPC will be created"
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