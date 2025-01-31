module "dc" {
    source      = "../dc"
    count       = var.create_domain_controller == false ? 0 : 1
    ami         = data.aws_ami.windows.id
    tagset      = var.tagset
    name        = var.name
    subnet_id   = coalesce(var.relay_subnet,one(module.network[*].relay_subnet))
    sg          = coalesce(var.public_sg,module.network[0].private_sg)

}

resource "sdm_resource" "dc" {
    count = var.create_domain_controller == false ? 0 : 1
    rdp {
        name     = "${var.name}-domain-controller"
        hostname = one(module.dc[*].dc_fqdn)
        username = one(module.dc[*].dc_username)
        password = one(module.dc[*].dc_password)

        port = 3389
        tags = one(module.dc[*].thistagset)

    }
}