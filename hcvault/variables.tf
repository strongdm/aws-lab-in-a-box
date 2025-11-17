variable "subnet_id" {
  description = "Subnet id in which to deploy the system"
  type        = string
  default     = null
}

variable "sg" {
  description = "Security group in which to deploy the system"
  type        = string
  default     = null
}

variable "tagset" {
  description = "Set of Tags to apply to StrongDM resources"
  type        = map(string)
}

variable "sshca" {
  description = "CA Certificate of the SSH CA"
  type        = string
}

variable "name" {
  description = "Arbitrary string to add to resources"
  type        = string
}

variable "target_user" {
  description = "User for Health check"
  type        = string
  default     = "ubuntu"
}

variable "vault_version" {
    description = "Version of HashiCorp Vault to download"
    type        = string
    default     = "1.18.4"
}

resource "random_password" "admin_password" {
  length      = 20
  special     = true
  min_numeric = 1
  min_upper   = 1
  min_lower   = 1
  min_special = 0
}

locals {
  admin_password = random_password.admin_password.result
  thistagset = merge (var.tagset, {
    network = "Private"
    class   = "sdminfra"
    Name    = "sdm-${var.name}-hashicorp-vault"
    }
  )  
}

variable "ami" {
  description = "AMI ID to be used for the target deployment"
  type        = string
}

variable "relay_instance_profile_arn" {
  description = "ARN of the StrongDM relay instance profile for Vault authentication binding"
  type        = string
}