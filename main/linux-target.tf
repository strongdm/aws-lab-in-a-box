module "linux-target" {
    source      = "../linux-target"
    count       = var.create_linux_target == false ? 0 : 1
    target_user = "ubuntu"
    ami         = data.aws_ami.ubuntu.id
    sshca       = data.sdm_ssh_ca_pubkey.ssh_pubkey_query.public_key
    tagset      = var.tagset
    name        = var.name
    subnet_id   = coalesce(var.relay_subnet,one(module.network[*].relay_subnet))
    sg          = coalesce(var.public_sg,module.network[0].private_sg)

}

resource "sdm_resource" "ssh-ca-target" {
        count = var.create_linux_target == false ? 0 : 1
    ssh_cert {
        name     = "ssh-ca-target"
        hostname = one(module.linux-target[*].target_hostname)
        username = one(module.linux-target[*].target_username)
        port     = 22
        tags = one(module.linux-target[*].thistagset)

    }
}