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
}
