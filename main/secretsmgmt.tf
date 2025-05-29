module "secretsmgmt" {
  source       = "../secretsmgmt"
  //count        = (try(var.domain_users) == false && var.create_managedsecrets == false && var.create_domain_controller == false) ? 0 : 1
  for_each = { for index, user in (var.create_managedsecrets ? (coalesce(var.domain_users, [])) : [] ):
    user.SamAccountName => user
  }
  se_pubkey    = sdm_secret_engine.ad[0].active_directory[0].public_key
  se_id        = sdm_secret_engine.ad[0].id
  user_dn      = "cn=${each.value.GivenName} ${each.value.Surname},cn=Users,dc=${var.name},dc=local"
  tags         = each.value.tags
  SamAccountName = each.value.SamAccountName

}

resource "sdm_secret_engine" "ad" {
  count     = (try(var.domain_users) == false && var.create_managedsecrets == false && var.create_domain_controller == false) ? 0 : 1
  active_directory {
    binddn                 = "CN=Domain Admin,CN=Users,DC=${var.name},DC=local"
    bindpass               = one(module.dc[*].domain_password)
    insecure_tls           = true
    name                   = "${var.name}AD"
    secret_store_id        = resource.sdm_secret_store.awssecretsmanager.id
    secret_store_root_path = "${var.name}AD"
    url                    = "ldaps://${one(module.dc[*].dc_fqdn)}/"
    max_backoff_duration   = "24h0m0s" 
  }
}