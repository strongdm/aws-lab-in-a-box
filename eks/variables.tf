variable "subnet_id" {
  description = "Subnet id in which to deploy the system"
  type        = list
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

variable "role" {
  description = "Gateway Role to associate"
  type        = string
}

locals {
  thistagset = merge (var.tagset, {
    network = "Private"
    class   = "target"
    }
  )  
}