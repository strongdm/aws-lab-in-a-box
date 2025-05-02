#--------------------------------------------------------------
# Windows Target Module Variables
#
# This file defines all input variables needed for the Windows target module.
# These variables control the network placement, domain integration, 
# authentication, and identification of the Windows instance used for
# RDP access demonstrations with StrongDM.
#--------------------------------------------------------------

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

variable "private_key_pem" {
  description = "Key to decrypt the initial admin password as provided by the DC module"
  type        = string
  default     = null
}

variable "key_name" {
  description = "Key to encrypt the initial admin password as provided by the DC module"
  type        = string
  default     = null
}

variable "dc_ip" {
  description = "IP of the domain controller"
  type        = string
  default     = null
}

variable "domain_password" {
  description = "Password of the domain admin to join"
  type        = string
  default     = null
}