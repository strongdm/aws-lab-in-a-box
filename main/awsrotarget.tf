#--------------------------------------------------------------
# AWS Read-Only Access Target Configuration
#
# This file creates an AWS IAM role that provides read-only access to AWS
# resources and registers it with StrongDM as both CLI and Console resources.
# This demonstrates how StrongDM can manage secure access to cloud platforms
# without sharing or distributing long-lived credentials.
#
# Components:
# - IAM role with read-only permissions
# - StrongDM CLI resource for programmatic access
# - StrongDM Console resource for web-based access
#--------------------------------------------------------------

# Create the AWS read-only role using the awsro module
module "awsro" {
  source = "../awsro"                         # Reference to the AWS Read-Only module
  count  = var.create_aws_ro == false ? 0 : 1 # Conditionally create based on feature flag
  name   = var.name                           # Name prefix for unique resource naming
  tagset = var.tagset                         # Tags for resource identification
  role   = aws_iam_role.gateway.arn           # Gateway role ARN for assume role permissions

}

# Register an AWS CLI resource in StrongDM for programmatic access
resource "sdm_resource" "awsrocli" {
  count = var.create_aws_ro == false ? 0 : 1
  aws_instance_profile {
    name     = "${var.name}-aws-cli-ro"                    # Resource name in StrongDM
    region   = data.aws_region.current.name                # AWS region for the profile
    role_arn = one(module.awsro[*].ec2_read_only_role_arn) # ARN of the read-only role

    tags = merge(var.tagset, {
      network       = "Public" # Tagged as public for visibility
      class         = "target" # Identifies as a target resource
      sdm__cloud_id = one(module.awsro[*].ec2_read_only_role_arn)
      }
    )
  }
}

# Register an AWS Console resource in StrongDM for web-based access
resource "sdm_resource" "awsroconsole" {
  count = var.create_aws_ro == false ? 0 : 1
  aws_console {
    name      = "aws-console-ro"                            # Resource name in StrongDM
    region    = data.aws_region.current.name                # AWS region for the console
    role_arn  = one(module.awsro[*].ec2_read_only_role_arn) # ARN of the read-only role
    subdomain = "aws${var.name}"                            # Subdomain for console access

    tags = merge(var.tagset, {
      network       = "Public" # Tagged as public for visibility
      class         = "target" # Identifies as a target resource
      sdm__cloud_id = one(module.awsro[*].ec2_read_only_role_arn)
      }
    )
  }
}