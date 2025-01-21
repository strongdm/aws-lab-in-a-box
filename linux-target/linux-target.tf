resource "aws_instance" "ssh-target" {
  ami                         = var.ami
  instance_type               = "t2.micro"
  subnet_id                   = var.subnet_id
  user_data_replace_on_change = true
  vpc_security_group_ids      = [var.sg]
  
  user_data = templatefile("../linux-target/ca-provision.tpl", {
    target_user        = var.target_user
    sshca              = var.sshca
  })

    tags = local.thistagset
  
}

locals {
  thistagset = merge (var.tagset, {
    network = "Private"
    class   = "target"
    Name    = "sdm-${var.name}-target-ssh"
    }
  )  
}