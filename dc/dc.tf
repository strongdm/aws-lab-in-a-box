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
  
  # Deploy the PowerShell script that sets up the domain controller
  user_data              = templatefile("../dc/install-dc.ps1.tpl", {
    name     = var.name
    password = random_password.admin_password.result
    rdpca    = var.rdpca
    
    domain_users = var.domain_users
    }
  )

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

# Generate a key pair for secure communication with the Windows instance
resource "tls_private_key" "windows" {
  algorithm = "RSA"
}

# Create an AWS key pair using the generated key
resource "aws_key_pair" "windows" {
  key_name   = "${var.name}-windows-key"
  public_key = tls_private_key.windows.public_key_openssh
  tags = local.thistagset
}


