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

variable "name" {
  description = "Arbitrary string to add to resources"
  type        = string
}

variable "ami" {
  description = "AMI ID to be used for the target deployment"
  type        = string
}

variable "target_user" {
  description = "User for Health check"
  type        = string
  default     = "ubuntu"
}



resource "random_password" "admin_password" {
  length      = 20
  special     = false
  min_numeric = 1
  min_upper   = 1
  min_lower   = 1

}

locals {
  admin_password = random_password.admin_password.result
  is_linux = length(regexall("c:", lower(abspath(path.root)))) > 0
  interpreter = local.is_linux ? "powershell" : "bash"
  script      = format("%s/%s",path.module,local.is_linux ? "windowsrdpca.ps1" : "windowsrdpca.sh")
  thistagset = merge (var.tagset, {
    network = "Private"
    class   = "sdminfra"
    Name    = "sdm-${var.name}-domain-controller"
    }
  )  
}