#--------------------------------------------------------------
# Domain Controller Module for StrongDM Integration
#
# This module creates a Windows domain controller in AWS that serves as the 
# foundation for Windows authentication in the StrongDM lab environment.
# It sets up Active Directory Domain Services (ADDS) and Active Directory
# Certificate Services (ADCS) to enable certificate-based authentication.
#
# Components:
# - Windows Server EC2 instance configured as domain controller
# - Certificate Authority for RDP certificate authentication
# - Required key pairs and security configurations
#--------------------------------------------------------------

# Create a Windows Server instance to be configured as a domain controller
resource "aws_instance" "dc" {
  instance_type = "t2.medium"
  ami           = var.ami

  user_data_replace_on_change = true

  # Enable password retrieval for the Windows administrator account
  get_password_data      = true
  key_name               = aws_key_pair.windows.key_name
  vpc_security_group_ids = [var.sg]
  subnet_id              = var.subnet_id

  # Attach IAM instance profile for S3 access
  iam_instance_profile = aws_iam_instance_profile.dc.name

  # Deploy minimal bootstrap script that downloads the full script from S3
  user_data = local.bootstrap_script

  # Provide sufficient disk space for AD DS and AD CS
  root_block_device {
    volume_size = 40
  }

  tags = local.thistagset
}

# Retrieve the RDP CA certificate from StrongDM using the appropriate script
# based on the operating system (bash for Linux/macOS, PowerShell for Windows)
//data "external" "rdpcertificate" {
//    program = [local.interpreter, local.script]
//}

locals {
  # Compute hash of domain users to trigger recreation when user list changes
  domain_users_hash = var.domain_users != null ? md5(jsonencode([for user in var.domain_users : {
    SamAccountName = user.SamAccountName
    GivenName      = user.GivenName
    Surname        = user.Surname
    domainadmin    = try(user.domainadmin, false)
  }])) : ""

  # Select the appropriate installation script based on AMI type
  # Packer AMI: Use optimized script (skips feature installation, ~11 min deployment)
  # Vanilla AMI: Use full script (installs all features, ~18-25 min deployment)
  install_script_template = var.use_packer_ami ? "${path.module}/install-dc-from-ami.ps1.tpl" : "${path.module}/install-dc.ps1.tpl"

  # Render the full PowerShell installation script using the selected template
  install_dc_rendered = templatefile(local.install_script_template, {
    name              = var.name
    password          = random_password.admin_password.result
    rdpca_base64      = base64encode(var.rdpca) # Base64 encode to avoid parsing issues
    domain_users_hash = local.domain_users_hash # Hash ensures user_data changes trigger recreation
    s3_bucket         = aws_s3_bucket.domain_users.id
    s3_key            = "domain-users.json"
    has_domain_users  = var.domain_users != null
  })

  # Minimal bootstrap script that downloads and executes the full script from S3
  # This keeps user_data small to avoid the 16KB limit
  bootstrap_script = <<-EOT
    <persist>true</persist>
    <powershell>
    # Bootstrap script to download and execute the full DC installation script from S3
    # Domain Users Hash: ${local.domain_users_hash}
    # Script Hash: ${md5(local.install_dc_rendered)}
    # These hashes ensure user_data changes when configuration changes

    $bucketName = "${aws_s3_bucket.domain_users.id}"
    $scriptKey = "install-dc.ps1"
    $scriptPath = "C:\install-dc.ps1"
    $logPath = "C:\bootstrap.log"

    Start-Transcript -Path $logPath -Append
    "Starting DC installation bootstrap at $(Get-Date)"

    # Check if setup is already complete
    if (Test-Path "C:\sdm.done") {
        "DC setup already completed. Exiting bootstrap."
        Stop-Transcript
        exit 0
    }

    try {
        # Get region from instance metadata
        $region = Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/placement/region" -TimeoutSec 5
        "Instance region: $region"

        # Check if AWS Tools for PowerShell is available
        "Checking for AWS Tools for PowerShell..."
        $awsToolsAvailable = $null -ne (Get-Command -Name Read-S3Object -ErrorAction SilentlyContinue)

        if (-not $awsToolsAvailable) {
            "AWS Tools not found. Installing AWS.Tools.S3..."
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            Install-Module -Name AWS.Tools.S3 -Force -AllowClobber
            Import-Module AWS.Tools.S3
            "AWS Tools installed successfully"
        } else {
            "AWS Tools already available"
        }

        # Download the installation script from S3 using IAM instance profile credentials
        "Downloading installation script from s3://$bucketName/$scriptKey"
        Read-S3Object -BucketName $bucketName -Key $scriptKey -File $scriptPath -Region $region
        "Script downloaded successfully"

        # Execute the installation script
        "Executing installation script..."
        & PowerShell.exe -ExecutionPolicy Bypass -File $scriptPath
        "Installation script completed"
    } catch {
        "ERROR: Bootstrap failed: $_"
        "Exception: $($_.Exception.Message)"
        exit 1
    }

    Stop-Transcript
    </powershell>
  EOT
}

# Generate a key pair for secure communication with the Windows instance
resource "tls_private_key" "windows" {
  algorithm = "RSA"
}

# Create an AWS key pair using the generated key
resource "aws_key_pair" "windows" {
  key_name   = "${var.name}-windows-key"
  public_key = tls_private_key.windows.public_key_openssh
  tags       = local.thistagset
}

#--------------------------------------------------------------
# S3 Bucket and Object for Domain Users
#
# This S3 bucket stores the domain users JSON file that will be
# downloaded by the domain controller during initialization.
# This approach avoids user_data size limits for large user lists.
#--------------------------------------------------------------

# Create S3 bucket for storing domain users configuration
resource "aws_s3_bucket" "domain_users" {
  bucket_prefix = "${lower(var.name)}-dcu-"
  tags          = local.thistagset

  force_destroy = true # Allow destruction even with objects inside
}

# Block public access to the bucket
resource "aws_s3_bucket_public_access_block" "domain_users" {
  bucket = aws_s3_bucket.domain_users.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Upload domain users as JSON file to S3
# This file will be downloaded by the DC during initialization
resource "aws_s3_object" "domain_users" {
  count  = var.domain_users != null ? 1 : 0
  bucket = aws_s3_bucket.domain_users.id
  key    = "domain-users.json"
  content = jsonencode([for user in var.domain_users : {
    SamAccountName = user.SamAccountName
    GivenName      = user.GivenName
    Surname        = user.Surname
    domainadmin    = try(user.domainadmin, false) # Include domainadmin field, default to false
  }])

  # ETag ensures object is updated when content changes
  etag = md5(jsonencode([for user in var.domain_users : {
    SamAccountName = user.SamAccountName
    GivenName      = user.GivenName
    Surname        = user.Surname
    domainadmin    = try(user.domainadmin, false)
  }]))

  tags = local.thistagset
}

# Upload the full PowerShell installation script to S3
# This avoids user_data size limits
resource "aws_s3_object" "install_script" {
  bucket  = aws_s3_bucket.domain_users.id
  key     = "install-dc.ps1"
  content = local.install_dc_rendered

  # ETag ensures object is updated when content changes
  etag = md5(local.install_dc_rendered)

  tags = local.thistagset
}

#--------------------------------------------------------------
# IAM Role and Instance Profile for S3 Access
#
# This IAM role allows the domain controller EC2 instance to
# download the domain users JSON file from S3 during initialization.
#--------------------------------------------------------------

# IAM role for the domain controller instance
resource "aws_iam_role" "dc" {
  name_prefix = "${var.name}-dc-role-"
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

# IAM policy to allow reading from the domain users S3 bucket and writing to Parameter Store
resource "aws_iam_role_policy" "dc_s3_access" {
  name_prefix = "${var.name}-dc-s3-ssm-"
  role        = aws_iam_role.dc.id

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
          aws_s3_bucket.domain_users.arn,
          "${aws_s3_bucket.domain_users.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:PutParameter",
          "ssm:GetParameter",
          "ssm:DeleteParameter"
        ]
        Resource = "arn:aws:ssm:*:*:parameter/${var.name}/dc/*"
      }
    ]
  })
}

# Instance profile to attach the IAM role to the EC2 instance
resource "aws_iam_instance_profile" "dc" {
  name_prefix = "${var.name}-dc-profile-"
  role        = aws_iam_role.dc.name
  tags        = local.thistagset
}


