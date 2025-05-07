output "ec2_read_only_role_arn" {
  description = "value of the ARN of the EC2 read-only role"
  # This output provides the ARN of the IAM role created in this module
  # It can be used in other modules or outputs to reference this role
  value = aws_iam_role.ec2_read_only_role.arn
}