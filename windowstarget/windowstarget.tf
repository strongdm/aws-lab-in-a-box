#--------------------------------------------------------------
# Windows Target Module for StrongDM Integration
#
# This module creates a Windows Server instance that joins an Active Directory
# domain and serves as an RDP target for StrongDM access control demonstrations.
# It enables both password-based and certificate-based authentication through
# StrongDM when integrated with the domain controller.
#
# Components:
# - Windows Server EC2 instance in a private subnet
# - Domain join automation via PowerShell script
# - RDP configuration for certificate authentication compatibility
# - Security group rules allowing RDP access
#--------------------------------------------------------------

# Create a Windows Server instance configured to join a domain and serve as an RDP target
resource "aws_instance" "windowstarget" {
  instance_type = "t2.medium" # Medium instance with sufficient resources for Windows Server
  ami           = var.ami     # Windows Server AMI ID passed from variables

  user_data_replace_on_change = true # Ensure user data changes trigger instance replacement

  # Enable password retrieval for the initial administrator password
  get_password_data      = true          # Allows retrieving the Windows administrator password
  key_name               = var.key_name  # Key pair for decrypting the administrator password
  vpc_security_group_ids = [var.sg]      # Security group allowing RDP and domain communication
  subnet_id              = var.subnet_id # Subnet ID for deployment (typically private subnet)

  # Deploy PowerShell script that configures the Windows instance to join the domain
  user_data = templatefile("${path.module}/join-domain.ps1.tpl", {
    name            = var.name            # Used for domain name construction (name.local)
    dc_ip           = var.dc_ip           # IP address of the domain controller for DNS configuration
    domain_password = var.domain_password # Password for the domain admin account to join the domain
    }
  )

  # Provide sufficient disk space for Windows Server and applications
  root_block_device {
    volume_size = 40 # 40GB is recommended minimum for Windows Server
  }

  # Apply consistent tagging for resource management and identification
  tags = local.thistagset
}

# Define a standardized tag set that includes Windows-specific information
locals {
  thistagset = merge(var.tagset, {
    network = "Private"                        # Indicates this is a private network resource
    class   = "target"                         # Identifies this as a StrongDM target resource
    Name    = "sdm-${var.name}-windows-target" # Provides a consistent naming convention
    }
  )
}