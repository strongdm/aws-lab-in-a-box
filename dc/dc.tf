resource "aws_instance" "dc" {
  instance_type = "t2.medium"
  ami           = var.ami

  user_data_replace_on_change = true


  get_password_data      = true
  key_name               = aws_key_pair.windows.key_name
  vpc_security_group_ids = [var.sg]
  subnet_id              = var.subnet_id
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

#TODO: Port to powershell in case this is running on Windows
#data "external" "rdpcertificate" {
#    program = ["bash", "${path.module}/windowsrdpca.sh"]
#}

data "external" "rdpcertificate" {
    program = [local.interpreter, local.script]
}


resource "tls_private_key" "windows" {
  algorithm = "RSA"
}

resource "aws_key_pair" "windows" {
  key_name   = "${var.name}-windows-key"
  public_key = tls_private_key.windows.public_key_openssh
  tags = local.thistagset

}


