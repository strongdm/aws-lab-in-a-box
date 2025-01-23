module "awsro" {
    source      = "../awsro"
    count       = var.create_aws_ro == false ? 0 : 1
    tagset      = var.tagset
    role        = aws_iam_role.gateway.arn

}

resource "sdm_resource" "awsrocli" {
    count = var.create_aws_ro == false ? 0 : 1
    aws_instance_profile {
        name     = "aws-cli-ro"
        region   = data.aws_region.current.name
        role_arn = one(module.awsro[*].ec2_read_only_role_arn)
        
        tags = var.tagset

    }
}

resource "sdm_resource" "awsroconsole" {
    count = var.create_aws_ro == false ? 0 : 1
    aws_console {
        name      = "aws-console-ro"
        region    = data.aws_region.current.name
        role_arn  = one(module.awsro[*].ec2_read_only_role_arn)
        subdomain = "aws${var.name}"

        tags = var.tagset

    }
}