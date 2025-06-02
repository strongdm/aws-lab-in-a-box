#--------------------------------------------------------------
# AWS Read-Only Role Module for StrongDM Integration
#
# This module creates an IAM role that provides read-only access to AWS resources,
# which can be assumed by both EC2 instances and the StrongDM gateway role.
# It enables secure, controlled access to AWS resources through StrongDM.
#
# Components:
# - IAM Role with trust relationship to EC2 and the gateway role
# - IAM Policy attachment for ReadOnlyAccess
#--------------------------------------------------------------

# Create a role that can be assumed by both EC2 service and the gateway role
resource "aws_iam_role" "ec2_read_only_role" {
  name               = "EC2ReadOnlyRole"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role_policy.json
  tags               = var.tagset
}

# Define the trust relationship policy allowing EC2 service and the gateway role to assume this role
data "aws_iam_policy_document" "ec2_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    principals {
      type        = "AWS"
      identifiers = [var.role]
    }
  }
}

# Attach the AWS managed ReadOnlyAccess policy to the role
# This provides read-only access to most AWS services including EC2, S3, etc.
resource "aws_iam_role_policy_attachment" "read_only_access_attachment" {
  role       = aws_iam_role.ec2_read_only_role.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess" # This is the managed policy for read-only access to most AWS services
}
