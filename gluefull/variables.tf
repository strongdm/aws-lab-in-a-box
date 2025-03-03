variable "tagset" {
  description = "Set of Tags to apply to StrongDM resources"
  type        = map(string)
}

variable "role" {
  description = "Gateway Role to associate"
  type        = string
}