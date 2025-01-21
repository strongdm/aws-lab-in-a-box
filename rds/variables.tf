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

variable "sg" {
  description = "Security group in which to deploy the system"
  type        = string
  default     = null
}

variable "db_name" {
  description = "Arbitrary DB Name"
  type        = string
  default     = "pagila"
}