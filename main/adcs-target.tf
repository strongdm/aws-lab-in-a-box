#--------------------------------------------------------------
# ADCS/NDES Target Configuration
#
# This file creates a standalone Windows ADCS + NDES server and joins it
# to the domain controller's Active Directory. It is a parallel
# certificate model to the StrongDM RDP CA path (see dc-target.tf), not a
# replacement for it. The ADCS host is registered as its own StrongDM RDP
# resource, so it has an access path independent of RDP-hopping through the
# domain controller.
#
# Components:
# - A guard that fails the plan with an explicit message when the
#   domain controller is disabled, instead of passing null credentials
#   into the module
# - Windows Server EC2 instance running ADCS/NDES, joined to the domain
# - StrongDM resource registration for administrative RDP access
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

  # The ADCS instance reuses the DC's key pair (key_name above), so the DC's
  # private key also decrypts the ADCS instance's initial admin password.
  private_key_pem = one(module.dc[*].private_key_pem)

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

# Register the ADCS/NDES host as an RDP resource in StrongDM for
# administrative access, mirroring sdm_resource.dc. Registered while the
# multi-reboot ADCS install may still be running, so it can show unhealthy
# until the next health check catches up - see healthchecks.tf.
resource "sdm_resource" "adcs" {
  count = var.create_adcs == false ? 0 : 1
  rdp {
    name = "${var.name}-adcs-ndes" # Resource name in StrongDM

    # The AWS-assigned private DNS name, matching sdm_resource.dc and
    # sdm_resource.windows-target. NOT module.adcs's adcs_fqdn: the network
    # module sets no aws_vpc_dhcp_options, so the relay resolves via
    # AmazonProvidedDNS and cannot resolve the AD name.
    hostname = one(module.adcs[*].adcs_hostname)
    username = one(module.adcs[*].admin_username) # Local administrator username
    password = one(module.adcs[*].admin_password) # Decrypted local administrator password

    port = 3389 # Standard RDP port
    tags = merge(one(module.adcs[*].tagset), {
      sdm__cloud_id = one(module.adcs[*].adcs_instance_id)
    })
  }
}

# ADCS/NDES enrollment credentials for whichever StrongDM node carries them
# (var.adcs_credentials_node). Sourced from module.dc, not module.adcs:
# module.adcs depends on terraform_data.dc_ready, so referencing any of its
# outputs from aws_instance.relay would order the relay behind a DC health
# check that only the relay itself can service, deadlocking apply.
# module.adcs's own sdm_adcs_user/sdm_adcs_password outputs are pure
# pass-throughs of these same module.dc values, so nothing is lost by
# reconstructing them here. Empty string (not null) when create_adcs is
# false, so gw-provision.tpl always receives a defined value on both call
# sites. Note that referencing module.dc here gives aws_instance.relay a graph
# edge to that module whenever create_domain_controller is true, including with
# create_adcs = false: Terraform builds edges from references, not from
# evaluated conditionals. That only serialises the relay behind the DC
# instance; it creates no cycle and changes no rendered user_data.
locals {
  # Guards against evaluating module.dc's outputs when create_domain_controller
  # is false: module.dc is then an empty tuple, one(module.dc[*].x) is null,
  # and a null spliced into the string template below errors outright rather
  # than producing "". (adcs_requires_dc already fails the plan for this
  # combination with its own message; this only stops that failure from being
  # masked by an unrelated interpolation error.)
  adcs_dc_present = var.create_adcs && length(module.dc) > 0

  # lower() matches adcs/variables.tf's own domain_fqdn: the DC creates the
  # UPN with var.name's original casing, but AD UPN lookup is case-insensitive,
  # so folding to lowercase here is safe and keeps this in sync with adcs'
  # domain_fqdn for a mixed-case var.name.
  adcs_user     = local.adcs_dc_present ? "${one(module.dc[*].svc_relay_username)}@${lower(var.name)}.local" : ""
  adcs_password = local.adcs_dc_present ? one(module.dc[*].svc_relay_password) : ""

  adcs_relay_user       = var.adcs_credentials_node == "relay" ? local.adcs_user : ""
  adcs_relay_password   = var.adcs_credentials_node == "relay" ? local.adcs_password : ""
  adcs_gateway_user     = var.adcs_credentials_node == "gateway" ? local.adcs_user : ""
  adcs_gateway_password = var.adcs_credentials_node == "gateway" ? local.adcs_password : ""
}
