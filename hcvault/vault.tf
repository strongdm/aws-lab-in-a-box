/*
 * HashiCorp Vault Module for AWS
 * Creates a single-node HashiCorp Vault instance with AWS KMS integration
 * Configured with auto-unseal using AWS KMS keys
 * Uses IAM roles for authentication to AWS services
 */

# Get current AWS region and account information
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# KMS key for Vault auto-unsealing
resource "aws_kms_key" "vault_unseal" {
  description             = "KMS key for HashiCorp Vault auto-unsealing"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Vault to use the key for unsealing"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.vault.arn
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.thistagset
}

# KMS key alias for easier identification
resource "aws_kms_alias" "vault_unseal" {
  name          = "alias/${var.name}-vault-unseal"
  target_key_id = aws_kms_key.vault_unseal.key_id
}

# IAM role for Vault EC2 instance
resource "aws_iam_role" "vault" {
  name = "${var.name}-vault-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = local.thistagset
}

# IAM policy for Vault to use KMS for unsealing and EC2 authentication
resource "aws_iam_role_policy" "vault" {
  name = "${var.name}-vault-policy"
  role = aws_iam_role.vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "VaultKMSUnseal"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.vault_unseal.arn
      },
      {
        Sid    = "VaultEC2Authentication"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceAttribute",
          "ec2:DescribeRegions",
          "ec2:DescribeSnapshots",
          "ec2:DescribeVpcs",
          "iam:GetInstanceProfile",
          "iam:GetRole",
          "iam:ListInstanceProfiles",
          "iam:ListRoles"
        ]
        Resource = "*"
      }
    ]
  })
}

# Instance profile for the Vault EC2 instance
resource "aws_iam_instance_profile" "vault" {
  name = "${var.name}-vault-instance-profile"
  role = aws_iam_role.vault.name
  tags = local.thistagset
}

# EC2 instance for HashiCorp Vault
resource "aws_instance" "hcvault" {
  ami                    = var.ami
  instance_type          = "t3.small"
  vpc_security_group_ids = [var.sg]
  subnet_id             = var.subnet_id
  iam_instance_profile  = aws_iam_instance_profile.vault.name
  
  user_data_replace_on_change = true

  user_data = base64encode(templatefile("${path.module}/vault-provision.tpl", {
    sshca                      = var.sshca
    target_user                = var.target_user
    vault_version              = var.vault_version
    kms_key_id                 = aws_kms_key.vault_unseal.key_id
    region                     = data.aws_region.current.name
    relay_instance_profile_arn = var.relay_instance_profile_arn
  }))

  tags = merge(local.thistagset, {
    Name = "${var.name}-hcvault"
  })
}