variable "se_pubkey" {
  description = "Public Key of the Secret Engine"
  type        = string
}

variable "se_id" {
  description = "ID of the secret engine"
  type        = string
}

variable "tags" {
  description = "Tags to be added to the managed secret"
  type        = map
}

variable "user_dn" {
  description = "LDAP User DN for the managed user"
  type        = string
}

variable "SamAccountName" {
  description = "Username of the account"
  type        = string
}