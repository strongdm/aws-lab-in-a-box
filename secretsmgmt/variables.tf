#--------------------------------------------------------------
# Secrets Management Module Variables
#
# This file defines the input variables required for creating managed secrets
# for Active Directory domain users. These variables connect the managed
# secrets to the appropriate secret engine and provide the necessary
# information for user authentication and access control.
#--------------------------------------------------------------

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
  type        = map(any)
}

variable "user_dn" {
  description = "LDAP User DN for the managed user"
  type        = string
}

variable "SamAccountName" {
  description = "Username of the account"
  type        = string
}

variable "domain_name" {
  description = "Domain name for the managed user (e.g., 'europa'). If provided, will be appended to username as username@domain.local"
  type        = string
  default     = null
}