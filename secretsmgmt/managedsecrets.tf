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

//resource "sdm_managed_secret" "domain_users" {
//  for_each = { 
//    for index, user in data.external.managed_users:
//    user.result.SamAccountName => user
//    }
//   kv {
//    value = "foo"
//   }
//   active_directory {
//    user_dn = "CN=Phillip J Fry, OU=Users"
//   }
//
//
//  name   = each.value.result.SamAccountName
//  value = base64decode(each.value.result.user_dn)
//  secret_engine_id = sdm_secret_engine.ad.id
//  #policy = jsonencode({"passwordPolicy" = "Length: 20, Digits: 5, Symbols: 2, AllowRepeat: false, ExcludedCharacters: \"\", ExcludeUpperCase: false"})
//}

# Create an encrypted secret value containing the user's LDAP distinguished name
resource "sdm_managed_secret_value" "secret" {
  value = {
    user_dn = var.user_dn # LDAP DN for the domain user
  }
  public_key = var.se_pubkey # Public key from the secret engine for encryption
}

# Create a managed secret for the domain user that enables password rotation
resource "sdm_managed_secret" "secret" {

  //name = replace(substr(each.value.value.user_dn, index(each.value.value.user_dn, "=") + 1, index(each.value.value.user_dn, ",") - index(each.value.value.user_dn, "=") - 1), " ", "_")
  name             = var.SamAccountName                        # Windows username for the managed secret
  secret_engine_id = var.se_id                                 # Reference to the Active Directory secret engine
  value            = sdm_managed_secret_value.secret.encrypted # Encrypted secret value
  tags             = var.tags                                  # User-specific tags for access control
}
//data "external" "managed_users" {
//    program = ["/bin/bash", "${path.module}/userencrypt.sh"]
//    for_each = { for index, user in var.domain_users:
//      user.SamAccountName => user
//    }
//    query = {
//        SamAccountName = each.value.SamAccountName
//        GivenName      = each.value.GivenName
//        Surname        = each.value.Surname
//        Domain         = var.name
//        Key            = local_file.public_key.filename
//    }


//}
