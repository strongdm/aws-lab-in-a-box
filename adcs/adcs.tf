#--------------------------------------------------------------
# ADCS/NDES Server Configuration
#
# This file creates a Windows Server instance with Active Directory
# Certificate Services (ADCS) and Network Device Enrollment Service (NDES)
# configured as an intermediate CA for StrongDM certificate authentication.
#
# Components:
# - Windows Server EC2 instance
# - ADCS installation as Enterprise Subordinate CA
# - NDES configuration with IIS and Basic Authentication
# - Custom certificate template (copy of Smart Card Logon)
# - Registry configuration for NDES/MSCEP integration
#--------------------------------------------------------------

# Create the ADCS/NDES server instance
resource "aws_instance" "adcs" {
  instance_type = var.instance_type
  ami           = var.ami

  user_data_replace_on_change = true

  # Enable password retrieval for initial administrator access
  get_password_data      = true
  key_name               = var.key_name
  vpc_security_group_ids = [var.sg]
  subnet_id              = var.subnet_id

  # Deploy PowerShell script that:
  # 1. Renames computer and joins the domain
  # 2. Installs ADCS as subordinate CA
  # 3. Installs and configures NDES
  # 4. Creates StrongDM certificate template
  # 5. Configures registry settings
  # 6. Enables HTTPS in IIS with machine certificate
  user_data = templatefile("${path.module}/install-adcs-ndes.ps1.tpl", {
    computer_name            = local.computer_name
    domain_name              = var.domain_name
    domain_fqdn              = local.domain_fqdn
    dc_ip                    = var.dc_ip
    dc_fqdn                  = var.dc_fqdn
    domain_admin_user        = var.domain_admin_user
    domain_password          = var.domain_password
    ca_common_name           = local.ca_common_name
    certificate_template_name = var.certificate_template_name
    ndes_service_account     = var.ndes_service_account
  })

  # Provide sufficient disk space for Windows Server, ADCS, and certificate database
  root_block_device {
    volume_size = 60 # Increased for certificate database and logs
  }

  # Apply consistent tagging
  tags = local.thistagset
}
