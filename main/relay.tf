#--------------------------------------------------------------
# StrongDM Relay Configuration
#
# This file creates the StrongDM Relay infrastructure required for secure
# access to private resources in the AWS lab environment. The relay sits
# in a private subnet and facilitates connections from the gateway to
# protected resources without exposing those resources to the internet.
#
# Components:
# - EC2 instance running the StrongDM Relay service
# - Network configuration for private subnet communication
# - SSH access for administrative purposes
#--------------------------------------------------------------

# Create a StrongDM relay node in the control plane
resource "sdm_node" "relay" {
  relay {
    name = "sdm-${var.name}-lab-r" # Relay name visible in StrongDM
    tags = merge(var.tagset, {
      network = "Private"
      class   = "sdminfra"
      "eng__${var.name}AD" = true
      }
    )
  }
}

# Launch the EC2 instance that will run the StrongDM relay
resource "aws_instance" "relay" {
  ami                         = data.aws_ami.ubuntu.id      # Ubuntu AMI defined in amis.tf
  instance_type               = "t2.micro"                  # Small instance suitable for relay functions
  user_data_replace_on_change = true                        # Ensure user data changes trigger instance replacement
  key_name                    = aws_key_pair.relay.key_name # Key pair for SSH access

  # Use the same IAM instance profile as gateway for secrets access
  iam_instance_profile = aws_iam_instance_profile.gw_instance_profile.name

  # Bootstrap the relay using the same provisioning template as gateway
  user_data = templatefile("gw-provision.tpl", {
    sdm_relay_token = sdm_node.relay.relay[0].token # Token for relay registration
    target_user     = "ubuntu"                      # User to run the relay service
    sdm_domain      = data.env_var.sdm_api.value == "" ? "" : coalesce(join(".", slice(split(".", element(split(":", data.env_var.sdm_api.value), 0)), 1, length(split(".", element(split(":", data.env_var.sdm_api.value), 0))))), "")
  })

  # Use a dedicated network interface in the private subnet
  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.relay.id
  }

  tags = merge(var.tagset, {
    network = "Private"
    class   = "sdminfra"
    Name    = "sdm-${var.name}-lab-r"
    }
  )
}

# Create a network interface in the private subnet
resource "aws_network_interface" "relay" {
  subnet_id       = one(module.network[*].relay_subnet) # Place in a private subnet
  security_groups = [one(module.network[*].private_sg)] # Use the private security group
}

# Create an AWS key pair using the StrongDM-generated public key
resource "aws_key_pair" "relay" {
  key_name   = "${var.name}-relay-key"
  public_key = sdm_resource.relay.ssh[0].public_key
}

# Register the relay host as an SSH resource in StrongDM for administrative access
resource "sdm_resource" "relay" {
  ssh {
    name     = "${var.name}-relay"
    hostname = aws_network_interface.relay.private_ip
    username = "ubuntu"
    port     = 22

    tags = merge(var.tagset, {
      network = "Public" # Note: Using public tag to make visible, even though the resource is private
      class   = "sdminfra"
      }
    )
  }
}