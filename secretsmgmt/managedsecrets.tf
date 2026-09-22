#--------------------------------------------------------------
# Managed Secrets Module for StrongDM Domain Users
#
# This module creates managed secrets for Active Directory domain users,
# enabling automatic password rotation and secure credential management
# through StrongDM. Each domain user gets a dedicated managed secret that
# can be rotated on demand or on a schedule.
#
# Components:
# - Encrypted secret values for domain user credentials
# - Managed secrets integrated with Active Directory secret engine
# - User-specific tagging for access control and organization
#--------------------------------------------------------------

# Create an encrypted secret value containing the user's LDAP distinguished name.
#
# sdm_managed_secret_value is deprecated in favour of setting a base64 encoded
# JSON value on sdm_managed_secret directly, but that path cannot carry this
# payload: the provider encrypts the value client-side with a key whose limit
# is well under the size of a user_dn plus username, and returns
# "crypto/rsa: message too long for RSA key size". This resource encrypts with
# the secret engine's own 4096-bit public key instead, which fits comfortably.
resource "sdm_managed_secret_value" "secret" {
  value = {
    user_dn  = var.user_dn                                                                                     # LDAP DN for the domain user
    username = var.domain_name != null ? "${var.SamAccountName}@${var.domain_name}.local" : var.SamAccountName # Store the username with domain suffix if domain_name provided
  }
  public_key = var.se_pubkey # Public key from the secret engine for encryption
}

# Create a managed secret for the domain user that enables password rotation
resource "sdm_managed_secret" "secret" {
  name             = replace(var.SamAccountName, ".", "_")     # Windows username for the managed secret (periods replaced with underscores)
  secret_engine_id = var.se_id                                 # Reference to the Active Directory secret engine
  value            = sdm_managed_secret_value.secret.encrypted # Encrypted secret value
  tags             = var.tags                                  # User-specific tags for access control
}
