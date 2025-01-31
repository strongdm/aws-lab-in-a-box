module "windowstarget" {
    source      = "../windowstarget"
    count       = var.create_windows_target == false ? 0 : 1
    ami         = data.aws_ami.windows.id
    tagset      = var.tagset
    name        = var.name
    key_name    = one(module.dc[*].key_name)
    subnet_id   = coalesce(var.relay_subnet,one(module.network[*].relay_subnet))
    sg          = coalesce(var.public_sg,module.network[0].private_sg)
    dc_ip       = one(module.dc[*].dc_ip)
    
    domain_password = one(module.dc[*].domain_password)

    private_key_pem = (one(module.dc[*].private_key_pem))


}

resource "sdm_resource" "windows-target" {
    count = var.create_windows_target == false ? 0 : 1
    rdp {
        name     = "${var.name}-windows-password"
        hostname = one(module.windowstarget[*].windowstarget_fqdn)
        username = one(module.windowstarget[*].windowstarget_username)
        password = one(module.windowstarget[*].windowstarget_password)

        port = 3389
        tags = one(module.windowstarget[*].thistagset)

    }
}

resource "sdm_resource" "windows-target-rdp" {
    count = var.create_windows_target == false ? 0 : 1
    rdp_cert {
        name     = "${var.name}-windows-ca"
        hostname = one(module.windowstarget[*].windowstarget_fqdn)
        username = "${var.name}\\Administrator"
        
        port = 3389
        tags = one(module.windowstarget[*].thistagset)
    }
}
