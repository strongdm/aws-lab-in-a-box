module "s3ro" {
    source      = "../s3ro"
    count       = var.create_aws_s3ro == false ? 0 : 1
    name        = var.name
    tagset      = var.tagset
    role        = aws_iam_role.gateway.arn

}

resource "sdm_resource" "awss3rocli" {
    count = var.create_aws_s3ro == false ? 0 : 1
    aws_instance_profile {
        name     = "${var.name}-S3-cli-ro"
        region   = data.aws_region.current.name
        role_arn = one(module.s3ro[*].s3_read_only_role_arn)
        
        tags = merge (var.tagset, {
            network = "Public"
            class   = "target"
            service = "S3"
            permissions = "readonly"
            }
        ) 

    }
}

resource "sdm_resource" "awss3webconsole" {
    count = var.create_aws_s3ro == false ? 0 : 1
    aws_console {
        name      = "S3-console-ro"
        region    = data.aws_region.current.name
        role_arn  = one(module.s3ro[*].s3_read_only_role_arn)
        subdomain = "s3ro${var.name}"

        tags = merge (var.tagset, {
            network = "Public"
            class   = "target"
            service = "S3"
            permissions = "readonly"
            }
        )  

    }
}