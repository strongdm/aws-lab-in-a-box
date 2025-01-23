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