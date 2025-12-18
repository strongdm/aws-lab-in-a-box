#--------------------------------------------------------------
# ADCS/NDES Module Variables
#
# This module deploys a Windows Server with Active Directory Certificate
# Services (ADCS) and Network Device Enrollment Service (NDES) configured
# as an intermediate CA for StrongDM certificate-based authentication.
#
# The ADCS server integrates with an existing Active Directory domain
# and issues certificates using a custom template optimized for StrongDM.
#--------------------------------------------------------------

# Network configuration variables
variable "subnet_id" {
  description = "Subnet ID in which to deploy the ADCS server"
  type        = string
}

variable "sg" {
  description = "Security group ID for the ADCS server"
  type        = string
}

# Resource identification and metadata
variable "tagset" {
  description = "Set of tags to apply to all resources"
  type        = map(string)
}

variable "name" {
  description = "Name prefix for resources (e.g., 'Europa')"
  type        = string
}

# Windows Server configuration
variable "ami" {
  description = "AMI ID for Windows Server 2019 (or compatible version)"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type for the ADCS server"
  type        = string
  default     = "t3.medium"
}

variable "key_name" {
  description = "EC2 key pair name for password retrieval"
  type        = string
}

# Active Directory integration
variable "domain_name" {
  description = "Active Directory domain name (without .local suffix, e.g., 'Europa')"
  type        = string
}

variable "dc_ip" {
  description = "IP address of the domain controller for DNS configuration"
  type        = string
}

variable "dc_fqdn" {
  description = "Fully qualified domain name of the domain controller (e.g., 'ec2amaz-abc123.europa.local')"
  type        = string
}

variable "domain_admin_user" {
  description = "Domain administrator username (e.g., 'Administrator')"
  type        = string
  default     = "Administrator"
}

variable "domain_password" {
  description = "Domain administrator password"
  type        = string
  sensitive   = true
}

# ADCS/NDES configuration
variable "ca_common_name" {
  description = "Common Name for the intermediate CA certificate"
  type        = string
  default     = null
}

variable "certificate_template_name" {
  description = "Name of the certificate template to create for StrongDM"
  type        = string
  default     = "StrongDM"
}

variable "ndes_service_account" {
  description = "Service account for NDES (will be created if it doesn't exist)"
  type        = string
  default     = "NDESService"
}

# Local variables for module operation
locals {
  # CA common name defaults to "<Name>-SubCA"
  ca_common_name = coalesce(var.ca_common_name, "${var.name}-SubCA")

  # Full domain name
  domain_fqdn = "${lower(var.domain_name)}.local"

  # Computer name for domain join
  computer_name = "${var.name}-adcs"

  # ADCS server FQDN
  server_fqdn = "${local.computer_name}.${local.domain_fqdn}"

  # Construct consistent tag set
  thistagset = merge(var.tagset, {
    network = "Private"
    class   = "adcs"
    Name    = "sdm-${var.name}-adcs-ndes"
  })

  # Render the full PowerShell installation script
  install_adcs_rendered = templatefile("${path.module}/install-adcs-ndes.ps1.tpl", {
    computer_name             = local.computer_name
    domain_name               = var.domain_name
    domain_fqdn               = local.domain_fqdn
    dc_ip                     = var.dc_ip
    dc_fqdn                   = var.dc_fqdn
    domain_admin_user         = var.domain_admin_user
    domain_password           = var.domain_password
    ca_common_name            = local.ca_common_name
    certificate_template_name = var.certificate_template_name
    ndes_service_account      = var.ndes_service_account
  })

  # Minimal bootstrap script that downloads and executes the full script from S3
  # This keeps user_data small to avoid the 16KB limit
  bootstrap_script = <<-EOT
    <persist>true</persist>
    <powershell>
    # Bootstrap script to download and execute the full ADCS installation script from S3
    # Script Hash: ${md5(local.install_adcs_rendered)}
    # This hash ensures user_data changes when configuration changes

    $bucketName = "${aws_s3_bucket.adcs_scripts.id}"
    $scriptKey = "install-adcs.ps1"
    $scriptPath = "C:\install-adcs.ps1"
    $logPath = "C:\bootstrap.log"

    Start-Transcript -Path $logPath -Append
    "Starting ADCS installation bootstrap at $(Get-Date)"

    # Check if setup is already complete
    if (Test-Path "C:\ADCSSetup.done") {
        "ADCS setup already completed. Exiting bootstrap."
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
