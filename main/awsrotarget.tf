module "awsro" {
    source      = "../awsro"
    count       = var.create_aws_ro == false ? 0 : 1
    tagset      = var.tagset
    role        = aws_iam_role.gateway.arn

}

resource "sdm_resource" "awsrocli" {
    count = var.create_aws_ro == false ? 0 : 1
    aws_instance_profile {
        name     = "${var.name}-aws-cli-ro"
        region   = data.aws_region.current.name
        role_arn = one(module.awsro[*].ec2_read_only_role_arn)
        
        tags = merge (var.tagset, {
            network = "Public"
            class   = "target"
            }
        ) 

    }
}

resource "sdm_resource" "awsroconsole" {
    count = var.create_aws_ro == false ? 0 : 1
    aws_console {
        name      = "aws-console-ro"
        region    = data.aws_region.current.name
        role_arn  = one(module.awsro[*].ec2_read_only_role_arn)
        subdomain = "aws${var.name}"

        tags = merge (var.tagset, {
            network = "Public"
            class   = "target"
            }
        )  

    }
}