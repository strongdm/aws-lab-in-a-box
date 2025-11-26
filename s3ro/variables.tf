variable "name" {
  description = "Arbitrary string to add to resources for identification and uniqueness"
  type        = string
}

variable "tagset" {
  description = "Set of Tags to apply to StrongDM resources"
  type        = map(string)
}

variable "role" {
  description = "Gateway Role to associate"
  type        = string
}