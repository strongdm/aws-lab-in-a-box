#--------------------------------------------------------------
# Domain Controller Configuration
#
# This file creates a Windows Server domain controller in AWS and registers
# it with StrongDM for administrative RDP access. The domain controller is
# a foundational component that provides Active Directory services and 
# certificate authority capabilities for Windows certificate authentication.
#
# Components:
# - Windows Server domain controller in a private subnet
# - Active Directory Domain Services (AD DS) configuration
# - Active Directory Certificate Services (AD CS) configuration
# - StrongDM resource registration for administrative access
#--------------------------------------------------------------

# Create the domain controller using the dc module
module "dc" {
  source    = "../dc"                                                         # Reference to the domain controller module
  count     = var.create_domain_controller == false ? 0 : 1                   # Conditionally create based on feature flag
  ami       = data.aws_ami.windows.id                                         # Windows Server AMI defined in amis.tf
  tagset    = var.tagset                                                      # Tags for resource identification
  name      = var.name                                                        # Name prefix for resources and domain name
  subnet_id = coalesce(var.relay_subnet, one(module.network[*].relay_subnet)) # Private subnet
  sg        = coalesce(var.public_sg, module.network[0].private_sg)           # Security group
  rdpca     = data.sdm_rdp_ca_pubkey.rdp_pubkey_query.public_key
  domain_users = var.domain_users                                             # Set of additional domain users to be created
}

# Register the domain controller as an RDP resource in StrongDM for administrative access
resource "sdm_resource" "dc" {
  count = var.create_domain_controller == false ? 0 : 1
  rdp {
    name     = "${var.name}-domain-controller" # Resource name in StrongDM
    hostname = one(module.dc[*].dc_fqdn)       # Private DNS name of the domain controller
    username = one(module.dc[*].dc_username)   # Local administrator username
    password = one(module.dc[*].dc_password)   # Local administrator password

    port = 3389                         # Standard RDP port
    tags = one(module.dc[*].thistagset) # Tags for access control
  }
}