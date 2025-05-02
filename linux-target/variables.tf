#--------------------------------------------------------------
# Linux Target Module Variables
#
# This file defines all input variables needed for the Linux target module.
# These variables control the network placement, authentication, and 
# identification of the Linux instance used for SSH CA authentication demos.
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

variable "sshca" {
  description = "CA Certificate of the SSH CA"
  type        = string
}

variable "ami" {
  description = "AMI ID to be used for the target deployment"
  type        = string
}

variable "target_user" {
  description = "User for Health check and SSH access via StrongDM"
  type        = string
  default     = "ubuntu"
}