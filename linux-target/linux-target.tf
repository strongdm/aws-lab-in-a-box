#--------------------------------------------------------------
# Linux SSH Target Module for StrongDM Integration
#
# This module creates a Linux EC2 instance configured with SSH Certificate
# Authority (CA) authentication for secure access through StrongDM.
# It configures the instance to trust the StrongDM SSH CA, enabling
# certificate-based authentication without needing to manage SSH keys.
#
# Components:
# - Ubuntu EC2 instance in a private subnet
# - SSH CA configuration via user data script
# - Security group rules allowing SSH access
#--------------------------------------------------------------

# Create an EC2 instance configured as an SSH target
resource "aws_instance" "ssh-target" {
  ami                         = var.ami
  instance_type               = "t2.micro"
  subnet_id                   = var.subnet_id
  user_data_replace_on_change = true
  vpc_security_group_ids      = [var.sg]
  
  # Configure the instance with the StrongDM SSH CA through a bootstrap script
  # The script adds the CA to trusted CAs and configures the target user
  # TODO: Change to templatefile("${path.module}/ca-provision.tpl
  user_data = templatefile("../linux-target/ca-provision.tpl", {
    target_user        = var.target_user    # Username that will be allowed to login via SSH CA
    sshca              = var.sshca          # The SSH CA public key from StrongDM
  })

  # Apply consistent tagging for resource management and identification
  tags = local.thistagset
}

# Define a standardized tag set that includes target-specific information
locals {
  thistagset = merge (var.tagset, {
    network = "Private"                     # Indicates this is a private network resource
    class   = "target"                      # Identifies this as a StrongDM target resource
    Name    = "sdm-${var.name}-target-ssh"  # Provides a consistent naming convention
    }
  )  
}