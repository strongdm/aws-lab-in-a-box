module "gluefull" {
    source      = "../gluefull"
    count       = var.create_aws_gluefull == false ? 0 : 1
    name        = var.name
    tagset      = var.tagset
    role        = aws_iam_role.gateway.arn

}

resource "sdm_resource" "awsgluefullcli" {
    count = var.create_aws_gluefull == false ? 0 : 1
    aws_instance_profile {
        name     = "${var.name}-Glue-cli-full"
        region   = data.aws_region.current.name
        role_arn = one(module.gluefull[*].glue_role_arn)
        
        tags = merge (var.tagset, {
            network = "Public"
            class   = "target"
            service = "Glue"
            permissions = "full"
            }
        ) 

    }
}

resource "sdm_resource" "awsglefullconsole" {
    count = var.create_aws_gluefull == false ? 0 : 1
    aws_console {
        name      = "Glue-console-full"
        region    = data.aws_region.current.name
        role_arn  = one(module.gluefull[*].glue_role_arn)
        subdomain = "gluefull${var.name}"

        tags = merge (var.tagset, {
            network = "Public"
            class   = "target"
            service = "Glue"
            permissions = "full"
            }
        )  

    }
}