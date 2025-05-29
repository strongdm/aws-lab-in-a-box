#--------------------------------------------------------------
# Domain Controller Module Variables
#
# This file defines all input variables needed to configure the Windows
# domain controller for the StrongDM lab environment. It includes network
# configuration, naming, and security parameters.
#
# It also declares local variables for cross-platform compatibility and
# generates secure passwords for domain administration.
#--------------------------------------------------------------

# Network configuration variables
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

# Resource identification and metadata
variable "tagset" {
  description = "Set of Tags to apply to StrongDM resources"
  type        = map(string)
}

variable "name" {
  description = "Arbitrary string to add to resources"
  type        = string
}

# Windows configuration
variable "ami" {
  description = "AMI ID to be used for the target deployment"
  type        = string
}

variable "target_user" {
  description = "User for Health check"
  type        = string
  default     = "ubuntu"
}

# Generate a secure random password for the domain administrator
resource "random_password" "admin_password" {
  length      = 20
  special     = false  # Avoid special chars for better compatibility
  min_numeric = 1      # Ensure at least one number
  min_upper   = 1      # Ensure at least one uppercase letter
  min_lower   = 1      # Ensure at least one lowercase letter
}

variable "domain_users" {
  description = "Set of map of users to be created in the Directory"
  type        = set(object({
    SamAccountName = string
    GivenName      = string
    Surname        = string
    tags           = map(string)
    }))
  default     = null
}

# Local variables for module operation
locals {
  admin_password = random_password.admin_password.result
  
  # Determine the operating system to use the appropriate script
  # This checks if we're running on Windows (has a C: drive) to select the right script
  is_linux = length(regexall("c:", lower(abspath(path.root)))) > 0
  interpreter = local.is_linux ? "powershell" : "bash"
  script      = format("%s/%s",path.module,local.is_linux ? "windowsrdpca.ps1" : "windowsrdpca.sh")
  
  # Construct a consistent tag set for all resources in this module
  thistagset = merge (var.tagset, {
    network = "Private"
    class   = "sdminfra"
    Name    = "sdm-${var.name}-domain-controller"
    }
  )  
}

variable "rdpca" {
  description = "RDP CA to import into the domain controller"
  type = string
}