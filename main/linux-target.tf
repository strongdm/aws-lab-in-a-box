#--------------------------------------------------------------
# Linux Target Configuration
#
# This file creates a Linux server target in AWS and registers it with
# StrongDM for secure SSH access using certificate-based authentication.
# The Linux target demonstrates how StrongDM can provide secure access
# to servers without sharing or managing SSH keys.
#
# Components:
# - Linux EC2 instance in a private subnet
# - SSH certificate authority configuration
# - StrongDM resource registration with SSH CA authentication
#--------------------------------------------------------------

# Create the Linux target instance using the linux-target module
module "linux-target" {
  source      = "../linux-target"                                               # Reference to the linux-target module
  count       = var.create_linux_target == false ? 0 : 1                        # Conditionally create based on feature flag
  target_user = "ubuntu"                                                        # Username for SSH access
  ami         = data.aws_ami.ubuntu.id                                          # Ubuntu AMI defined in amis.tf
  sshca       = data.sdm_ssh_ca_pubkey.ssh_pubkey_query.public_key              # CA public key from StrongDM
  tagset      = var.tagset                                                      # Tags for resource identification
  name        = var.name                                                        # Name prefix for resources
  subnet_id   = coalesce(var.relay_subnet, one(module.network[*].relay_subnet)) # Private subnet
  sg          = coalesce(var.public_sg, module.network[0].private_sg)           # Security group

}

# Register the Linux target as a certificate-based SSH resource in StrongDM
resource "sdm_resource" "ssh-ca-target" {
  count = var.create_linux_target == false ? 0 : 1
  ssh_cert {
    name     = "${var.name}-ssh-ca-target"                 # Resource name in StrongDM
    hostname = one(module.linux-target[*].target_hostname) # Private IP of the target
    username = one(module.linux-target[*].target_username) # User configured for access
    port     = 22                                          # Standard SSH port
    tags     = merge(one(module.linux-target[*].thistagset), {
      sdm__cloud_id = one(module.linux-target[*].instance_id)
    })

  }
}