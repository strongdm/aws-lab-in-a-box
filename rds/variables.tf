#--------------------------------------------------------------
# RDS PostgreSQL Module Variables
#
# This file defines all input variables needed for the RDS PostgreSQL module.
# These variables control the network placement, database configuration,
# and identification of the PostgreSQL instance used for database access demos.
#--------------------------------------------------------------

variable "subnet_id" {
  description = "Subnet id in which to deploy the system"
  type        = list(any)
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