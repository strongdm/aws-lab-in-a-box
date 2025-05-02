#--------------------------------------------------------------
# Windows RDP Target Configuration
#
# This file creates a Windows Server instance that joins an Active Directory
# domain and registers it with StrongDM for secure RDP access. It demonstrates
# both password-based and certificate-based authentication methods for Windows
# access through StrongDM.
#
# Components:
# - Windows Server EC2 instance in a private subnet
# - Domain join configuration with the domain controller
# - StrongDM resource registration for both auth methods
#--------------------------------------------------------------

# Create the Windows target instance using the windowstarget module
module "windowstarget" {
  source    = "../windowstarget"                      # Reference to the windowstarget module
  count     = var.create_windows_target == false ? 0 : 1  # Conditionally create based on feature flag
  ami       = data.aws_ami.windows.id                 # Windows Server AMI defined in amis.tf
  tagset    = var.tagset                              # Tags for resource identification
  name      = var.name                                # Name prefix for resources
  key_name  = one(module.dc[*].key_name)              # Key pair from domain controller module
  subnet_id = coalesce(var.relay_subnet, one(module.network[*].relay_subnet))  # Private subnet
  sg        = coalesce(var.public_sg, module.network[0].private_sg)  # Security group
  dc_ip     = one(module.dc[*].dc_ip)                 # Domain controller IP for DNS configuration

  # Domain credentials for automated domain join
  domain_password = one(module.dc[*].domain_password)  # Password for domain admin account
  private_key_pem = (one(module.dc[*].private_key_pem))  # Key for decrypting admin password
}

# Register the Windows target with password authentication in StrongDM
resource "sdm_resource" "windows-target" {
  count = var.create_windows_target == false ? 0 : 1
  rdp {
    name     = "${var.name}-windows-password"        # Resource name in StrongDM
    hostname = one(module.windowstarget[*].windowstarget_fqdn)  # Private DNS name of target
    username = one(module.windowstarget[*].windowstarget_username)  # Admin username
    password = one(module.windowstarget[*].windowstarget_password)  # Admin password
    port     = 3389                                  # Standard RDP port
    tags     = one(module.windowstarget[*].thistagset)  # Tags for access control
  }
}

# Register the Windows target with certificate authentication in StrongDM
resource "sdm_resource" "windows-target-rdp" {
  count = var.create_windows_target == false ? 0 : 1
  rdp_cert {
    name     = "${var.name}-windows-ca"             # Resource name in StrongDM
    hostname = one(module.windowstarget[*].windowstarget_fqdn)  # Private DNS name of target
    username = "${var.name}\\Administrator"         # Domain admin username with domain prefix
    port     = 3389                                 # Standard RDP port
    tags     = one(module.windowstarget[*].thistagset)  # Tags for access control
  }
}
