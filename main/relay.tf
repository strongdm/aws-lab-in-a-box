resource "sdm_node" "relay" {
    relay {
        name = "sdm-${var.name}-lab-r"
        tags = merge (var.tagset, {
          network = "Private"
          class   = "sdminfra"
          }
        )
    }
}

resource "aws_instance" "relay" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t2.micro"
  user_data_replace_on_change = true
  key_name                    = aws_key_pair.relay.key_name

  iam_instance_profile = aws_iam_instance_profile.gw_instance_profile.name
  user_data = templatefile("gw-provision.tpl", {
    sdm_relay_token    = sdm_node.relay.relay[0].token
    target_user        = "ubuntu"
    sdm_domain         = data.env_var.sdm_api.value == "" ? "" : coalesce(join(".", slice(split(".", element(split(":", data.env_var.sdm_api.value), 0)), 1, length(split(".", element(split(":", data.env_var.sdm_api.value), 0))))),"")

  })
  network_interface {
    device_index = 0
    network_interface_id = aws_network_interface.relay.id
  }

    tags = merge (var.tagset, {
    network = "Private"
    class   = "sdminfra"
    Name    = "sdm-${var.name}-lab-r"
    }
  )
}
resource "aws_network_interface" "relay" {
  subnet_id       = one(module.network[*].relay_subnet)
  security_groups = [one(module.network[*].private_sg)]
}

resource "aws_key_pair" "relay" {
  key_name   = "${var.name}-relay-key"
  public_key = sdm_resource.relay.ssh[0].public_key
}

resource "sdm_resource" "relay" {
    ssh {
        name     = "${var.name}-relay"
        hostname = aws_network_interface.relay.private_ip
        username = "ubuntu"
        port     = 22
        
        tags = merge (var.tagset, {
          network = "Public"
          class   = "sdminfra"
          }
        )

    }
}