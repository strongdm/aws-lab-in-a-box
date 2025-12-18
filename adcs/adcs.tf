#--------------------------------------------------------------
# ADCS/NDES Server Configuration
#
# This file creates a Windows Server instance with Active Directory
# Certificate Services (ADCS) and Network Device Enrollment Service (NDES)
# configured as an intermediate CA for StrongDM certificate authentication.
#
# Components:
# - Windows Server EC2 instance
# - ADCS installation as Enterprise Subordinate CA
# - NDES configuration with IIS and Basic Authentication
# - Custom certificate template (copy of Smart Card Logon)
# - Registry configuration for NDES/MSCEP integration
# - S3 bucket for storing large installation script (avoids 16KB user_data limit)
# - IAM role for EC2 instance to download script from S3
#--------------------------------------------------------------

# Create the ADCS/NDES server instance
resource "aws_instance" "adcs" {
  instance_type = var.instance_type
  ami           = var.ami

  user_data_replace_on_change = true

  # Enable password retrieval for initial administrator access
  get_password_data      = true
  key_name               = var.key_name
  vpc_security_group_ids = [var.sg]
  subnet_id              = var.subnet_id

  # Attach IAM instance profile for S3 access
  iam_instance_profile = aws_iam_instance_profile.adcs.name

  # Deploy minimal bootstrap script that downloads the full script from S3
  user_data = local.bootstrap_script

  # Provide sufficient disk space for Windows Server, ADCS, and certificate database
  root_block_device {
    volume_size = 60 # Increased for certificate database and logs
  }

  # Apply consistent tagging
  tags = local.thistagset
}

#--------------------------------------------------------------
# S3 Bucket for Installation Scripts
#
# This S3 bucket stores the ADCS installation script that will be
# downloaded by the server during initialization.
# This approach avoids user_data size limits for large scripts.
#--------------------------------------------------------------

# Create S3 bucket for storing installation scripts
resource "aws_s3_bucket" "adcs_scripts" {
  bucket_prefix = "${lower(var.name)}-adcs-"
  tags          = local.thistagset

  force_destroy = true # Allow destruction even with objects inside
}

# Block public access to the bucket
resource "aws_s3_bucket_public_access_block" "adcs_scripts" {
  bucket = aws_s3_bucket.adcs_scripts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Upload the full PowerShell installation script to S3
# This avoids user_data size limits
resource "aws_s3_object" "install_script" {
  bucket  = aws_s3_bucket.adcs_scripts.id
  key     = "install-adcs.ps1"
  content = local.install_adcs_rendered

  # ETag ensures object is updated when content changes
  etag = md5(local.install_adcs_rendered)

  tags = local.thistagset
}

#--------------------------------------------------------------
# IAM Role and Instance Profile for S3 Access
#
# This IAM role allows the ADCS/NDES EC2 instance to
# download the installation script from S3 during initialization.
#--------------------------------------------------------------

# IAM role for the ADCS instance
resource "aws_iam_role" "adcs" {
  name_prefix = "${var.name}-adcs-role-"
  tags        = local.thistagset

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
}

# IAM policy to allow reading from the ADCS scripts S3 bucket
resource "aws_iam_role_policy" "adcs_s3_access" {
  name_prefix = "${var.name}-adcs-s3-"
  role        = aws_iam_role.adcs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.adcs_scripts.arn,
          "${aws_s3_bucket.adcs_scripts.arn}/*"
        ]
      }
    ]
  })
}

# Instance profile to attach the IAM role to the EC2 instance
resource "aws_iam_instance_profile" "adcs" {
  name_prefix = "${var.name}-adcs-profile-"
  role        = aws_iam_role.adcs.name
  tags        = local.thistagset
}
