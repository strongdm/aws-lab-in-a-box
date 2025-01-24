resource "aws_instance" "windowstarget" {
  instance_type = "t2.medium"
  ami           = var.ami

  user_data_replace_on_change = true


  get_password_data      = true
  key_name               = var.key_name
  vpc_security_group_ids = [var.sg]
  subnet_id              = var.subnet_id
  #TODO: Troubleshoot
  user_data              = templatefile("../windowstarget/join-domain.ps1.tpl", {
    name     = var.name
    dc_ip    = var.dc_ip

    domain_password = var.domain_password    
    }
  )

  root_block_device {
    volume_size = 40
  }

  tags = local.thistagset

}


locals {
  thistagset = merge (var.tagset, {
    network = "Private"
    class   = "target"
    Name    = "sdm-${var.name}-windows-target"
    }
  )

}