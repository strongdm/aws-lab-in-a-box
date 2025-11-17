module "hcvault" {
    source = "../hcvault"
    ami    = data.aws_ami.ubuntu.id
    count  = var.create_hcvault == false ? 0 : 1
    sshca  = data.sdm_ssh_ca_pubkey.ssh_pubkey_query.public_key
    tagset = var.tagset
    name   = var.name

    subnet_id   = coalesce(var.relay_subnet, one(module.network[*].relay_subnet)) # Private subnet
    sg          = coalesce(var.public_sg, module.network[0].private_sg) 

    relay_instance_profile_arn = aws_iam_instance_profile.gw_instance_profile.arn
    vault_version = var.vault_version

}

resource "sdm_resource" "ssh-hcvault" {
    count = var.create_hcvault == false ? 0 : 1
    depends_on = [ module.hcvault ]
    ssh_cert {
        name     = "${var.name}-hcvault"
        hostname = one(module.hcvault[*].ip)
        username = one(module.hcvault[*].target_user)
        port     = 22
        tags = one(module.hcvault[*].tagset)

    }
}

resource "sdm_secret_store" "hcvault" {
    count = var.create_hcvault == false ? 0 : 1
    vault_token {
        name = "HashiCorp Vault ${var.name}"
        tags = var.tagset
        server_address = "http://${one(module.hcvault[*].ip)}:8200"
    }
}