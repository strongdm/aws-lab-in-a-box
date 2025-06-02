#--------------------------------------------------------------
# AWS Read-Only Role Module Outputs
#
# This file defines the output values from the AWS read-only role module.
# The outputs provide the ARN of the created IAM role, which can be
# referenced by other modules for role assumption and resource access.
#--------------------------------------------------------------

output "ec2_read_only_role_arn" {
  description = "value of the ARN of the EC2 read-only role"
  # This output provides the ARN of the IAM role created in this module
  # It can be used in other modules or outputs to reference this role
  value = aws_iam_role.ec2_read_only_role.arn
}