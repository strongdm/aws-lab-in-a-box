#--------------------------------------------------------------
# Secrets Management Configuration
#
# This file configures StrongDM's secrets management capabilities by setting up
# an Active Directory secret engine that integrates with the domain controller.
# It enables automatic password rotation and secure credential management for
# domain users, demonstrating StrongDM's ability to eliminate static passwords
# and provide just-in-time access to Windows environments.
#
# Components:
# - Active Directory secret engine for credential management
# - Integration with AWS Secrets Manager as the backing store
# - Managed secrets for individual domain users
# - LDAP connection to domain controller for password operations
#--------------------------------------------------------------

# Create managed secrets for individual domain users using the secretsmgmt module
module "secretsmgmt" {
  source = "../secretsmgmt" # Reference to the secrets management module
  for_each = { for index, user in(var.create_managedsecrets && var.create_domain_controller ? (coalesce(var.domain_users, [])) : []) :
    user.SamAccountName => user # Create one instance per domain user
  }
  se_pubkey      = sdm_secret_engine.ad[0].active_directory[0].public_key                              # Public key from the AD secret engine
  se_id          = sdm_secret_engine.ad[0].id                                                          # Reference to the AD secret engine
  user_dn        = "cn=${each.value.GivenName} ${each.value.Surname},cn=Users,dc=${var.name},dc=local" # LDAP DN for the user
  tags           = each.value.tags                                                                     # User-specific tags for access control
  SamAccountName = each.value.SamAccountName                                                           # Windows username for the domain account

}

# Create an Active Directory secret engine for automated credential management
resource "sdm_secret_engine" "ad" {
  count = (var.create_domain_controller && (var.create_managedsecrets || try(var.domain_users, null) != null)) ? 1 : 0 # Only create when DC exists and secrets are needed
  active_directory {
    binddn                 = "CN=Domain Admin,CN=Users,DC=${var.name},DC=local" # Domain admin account for LDAP operations
    bindpass               = one(module.dc[*].domain_password)                  # Domain admin password from DC module
    insecure_tls           = true                                               # Allow self-signed certificates for lab environment
    name                   = "${var.name}AD"                                    # Name of the secret engine
    secret_store_id        = resource.sdm_secret_store.awssecretsmanager.id     # AWS Secrets Manager backing store
    secret_store_root_path = "${var.name}AD"                                    # Root path in Secrets Manager for this engine
    url                    = "ldaps://${one(module.dc[*].dc_fqdn)}/"            # LDAPS connection to domain controller
    max_backoff_duration   = "24h0m0s"                                          # Maximum retry backoff for failed operations
  }
}
