#--------------------------------------------------------------
# ADCS/NDES Target Configuration
#
# This file creates a standalone Windows ADCS + NDES server and joins it
# to the domain controller's Active Directory. It is a parallel
# certificate model to the StrongDM RDP CA path (see dc-target.tf), not
# a replacement: the ADCS host is deliberately not registered as a
# StrongDM resource yet, so debugging it means RDP through the domain
# controller.
#
# Components:
# - A guard that fails the plan with an explicit message when the
#   domain controller is disabled, instead of passing null credentials
#   into the module
# - Windows Server EC2 instance running ADCS/NDES, joined to the domain
#--------------------------------------------------------------

# ADCS joins the existing domain controller's Active Directory and derives
# its computer name as "<name>-adcs", which must fit Windows' 15-character
# NetBIOS limit. Fail the plan here with an explicit message rather than
# letting a null credential or an oversized computer name fail the domain
# join at runtime, roughly ten minutes in.
resource "terraform_data" "adcs_requires_dc" {
  count = var.create_adcs ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.create_domain_controller
      error_message = "create_adcs requires create_domain_controller = true; ADCS joins the existing domain controller's Active Directory."
    }
    precondition {
      condition     = length(var.name) <= 10
      error_message = "create_adcs derives the computer name \"${var.name}-adcs\", which must be 15 characters or fewer for a Windows NetBIOS name; keep var.name to 10 characters or fewer."
    }
  }
}

# Create the ADCS/NDES server using the adcs module
module "adcs" {
  source    = "../adcs"                                                       # Reference to the ADCS/NDES module
  count     = var.create_adcs == false ? 0 : 1                                # Conditionally create based on feature flag
  ami       = data.aws_ami.windows.id                                         # Windows Server AMI defined in amis.tf
  tagset    = var.tagset                                                      # Tags for resource identification
  name      = var.name                                                        # Name prefix for resources
  key_name  = one(module.dc[*].key_name)                                      # Key pair from domain controller module
  subnet_id = coalesce(var.relay_subnet, one(module.network[*].relay_subnet)) # Private subnet
  sg        = coalesce(var.public_sg, module.network[0].private_sg)           # Security group

  # Domain integration; domain_name takes var.name, since the DC module
  # builds dc=<name>,dc=local
  domain_name = var.name
  dc_ip       = one(module.dc[*].dc_ip)   # Domain controller IP for DNS configuration
  dc_fqdn     = one(module.dc[*].dc_fqdn) # Domain controller FQDN for domain join

  # Credentials for the automated domain join and the NDES/relay service identities
  domain_admin_user  = one(module.dc[*].domain_admin)       # Domain administrator username created by the DC module
  domain_password    = one(module.dc[*].domain_password)    # Password for the domain administrator account
  svc_ndes_password  = one(module.dc[*].svc_ndes_password)  # NDES IIS AppPool identity password
  svc_relay_password = one(module.dc[*].svc_relay_password) # Relay-to-NDES service account password (SDM_ADCS_PW)

  # The instance joins the domain during boot, so do not start it until the
  # domain controller reports ready. Depending on the guard above means a
  # failed precondition skips this module instead of evaluating it with
  # null credentials.
  depends_on = [terraform_data.dc_ready, terraform_data.adcs_requires_dc]
}
