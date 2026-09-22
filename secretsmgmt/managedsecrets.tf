#--------------------------------------------------------------
# Managed Secrets Module for StrongDM Domain Users
#
# This module creates managed secrets for Active Directory domain users,
# enabling automatic password rotation and secure credential management
# through StrongDM. Each domain user gets a dedicated managed secret that
# can be rotated on demand or on a schedule.
#
# Components:
# - Base64 encoded JSON credentials set directly on each managed secret
# - Managed secrets integrated with Active Directory secret engine
# - User-specific tagging for access control and organization
#--------------------------------------------------------------

# Create a managed secret for the domain user that enables password rotation.
# The credential is set directly as base64 encoded JSON; the separate encrypted
# value resource it replaces is deprecated.
resource "sdm_managed_secret" "secret" {
  name             = replace(var.SamAccountName, ".", "_") # Windows username for the managed secret (periods replaced with underscores)
  secret_engine_id = var.se_id                             # Reference to the Active Directory secret engine
  tags             = var.tags                              # User-specific tags for access control

  value = base64encode(jsonencode({
    user_dn  = var.user_dn                                                                                     # LDAP DN for the domain user
    username = var.domain_name != null ? "${var.SamAccountName}@${var.domain_name}.local" : var.SamAccountName # Store the username with domain suffix if domain_name provided
  }))
}
