module "s3full" {
    source      = "../s3full"
    count       = var.create_aws_s3full == false ? 0 : 1
    tagset      = var.tagset
    role        = aws_iam_role.gateway.arn

}

resource "sdm_resource" "awss3fullcli" {
    count = var.create_aws_s3full == false ? 0 : 1
    aws_instance_profile {
        name     = "${var.name}-S3-cli-full"
        region   = data.aws_region.current.name
        role_arn = one(module.s3full[*].s3_full_role_arn)
        
        tags = merge (var.tagset, {
            network = "Public"
            class   = "target"
            service = "S3"
            permissions = "full"
            }
        ) 

    }
}

resource "sdm_resource" "awss3fullconsole" {
    count = var.create_aws_s3full == false ? 0 : 1
    aws_console {
        name      = "S3-console-full"
        region    = data.aws_region.current.name
        role_arn  = one(module.s3full[*].s3_full_role_arn)
        subdomain = "s3full${var.name}"

        tags = merge (var.tagset, {
            network = "Public"
            class   = "target"
            service = "S3"
            permissions = "full"
            }
        )  

    }
}