resource "aws_instance" "dc" {
  instance_type = "t2.medium"
  ami           = var.ami

  user_data_replace_on_change = true


  get_password_data      = true
  key_name               = aws_key_pair.windows.key_name
  vpc_security_group_ids = [var.sg]
  subnet_id              = var.subnet_id
  #TODO: This script takes a bunch of reboots and a bunch of minutes... need to implement something to avoid provisioning domain machines until this is up
  user_data              = templatefile("../dc/install-dc.ps1.tpl", {
    name     = var.name
    password = random_password.admin_password.result
    rdpca    = data.external.rdpcertificate.result.certificate
    }
  )

  root_block_device {
    volume_size = 40
  }

  tags = local.thistagset

}

data "external" "rdpcertificate" {
    program = ["bash", "../dc/windowsrdpca.sh"]
}

resource "tls_private_key" "windows" {
  algorithm = "RSA"
}

resource "aws_key_pair" "windows" {
  key_name   = "${var.name}-windows-key"
  public_key = tls_private_key.windows.public_key_openssh
  tags = local.thistagset

}

resource "random_password" "admin_password" {
  length      = 20
  special     = true
  min_numeric = 1
  min_upper   = 1
  min_lower   = 1
  min_special = 1
}

locals {
  thistagset = merge (var.tagset, {
    network = "Private"
    class   = "sdminfra"
    Name    = "sdm-${var.name}-domain-controller"
    }
  )
#TODO... this is the original example from Guillermo but it looks super messy. Clean it up!
#  dc1_fqdn = "dc1.${var.name}.local"

#  dc1_prereq_ad_1 = "Import-Module ServerManager"
#  dc1_prereq_ad_2 = "Install-WindowsFeature AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools"
#  dc1_prereq_ad_3 = "Install-WindowsFeature DNS -IncludeAllSubFeature -IncludeManagementTools"
#  dc1_prereq_ad_4 = "Import-Module ADDSDeployment"
#  dc1_prereq_ad_5 = "Import-Module DnsServer"
#  dc1_prereq_cs_1 = "Install-AdcsCertificationAuthority -CAType StandaloneRootCa"

#  dc1_install_ad_1 = "Install-ADDSForest -DomainName ${var.name}.local -DomainNetbiosName ${var.name} -DomainMode WinThreshold -ForestMode WinThreshold "
#  dc1_install_ad_2 = "-DatabasePath C:/Windows/NTDS -SysvolPath C:/Windows/SYSVOL -LogPath C:/Windows/NTDS -NoRebootOnCompletion:$false -Force:$true "
#  dc1_install_ad_3 = "-SafeModeAdministratorPassword (ConvertTo-SecureString ${random_password.admin_password.result} -AsPlainText -Force)"

#  dc1_shutdown_command   = "shutdown -r -t 10"
#  dc1_exit_code_hack     = "exit 0"
#  dc1_powershell_command = "${local.dc1_prereq_ad_1}; ${local.dc1_prereq_ad_2}; ${local.dc1_prereq_ad_3}; ${local.dc1_prereq_ad_4}; ${local.dc1_prereq_ad_5}; ${local.dc1_prereq_cs_1}; ${local.dc1_install_ad_1}${local.dc1_install_ad_2}${local.dc1_install_ad_3}; ${local.dc1_shutdown_command}; ${local.dc1_exit_code_hack}"
}