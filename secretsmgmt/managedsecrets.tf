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



resource "sdm_managed_secret_value" "secret" {
  value = {
  user_dn = var.user_dn
  }
  public_key = var.se_pubkey
}

resource "sdm_managed_secret" "secret" {
    
  //name = replace(substr(each.value.value.user_dn, index(each.value.value.user_dn, "=") + 1, index(each.value.value.user_dn, ",") - index(each.value.value.user_dn, "=") - 1), " ", "_")
  name = var.SamAccountName
  secret_engine_id = var.se_id
  value = sdm_managed_secret_value.secret.encrypted
  tags  = var.tags
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
