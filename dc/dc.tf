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
  special     = false
  min_numeric = 1
  min_upper   = 1
  min_lower   = 1

}

locals {
  thistagset = merge (var.tagset, {
    network = "Private"
    class   = "sdminfra"
    Name    = "sdm-${var.name}-domain-controller"
    }
  )
}