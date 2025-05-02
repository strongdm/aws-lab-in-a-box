#--------------------------------------------------------------
# StrongDM Gateway Configuration
#
# This file creates the StrongDM Gateway infrastructure required for secure
# access to resources in the AWS lab environment. The gateway serves as the
# connection point for StrongDM clients to access protected resources.
#
# Components:
# - Elastic IP for consistent gateway addressing
# - IAM role with Secrets Manager access permissions
# - EC2 instance running the StrongDM Gateway service
# - Network configuration for public internet access
#--------------------------------------------------------------

# Elastic IP for the gateway to ensure a stable public endpoint
resource "aws_eip" "gateway" {
  domain = "vpc"

  tags = merge(var.tagset, {
    network = "Public"
    class   = "sdminfra"
    }
  )
}

# IAM role for the gateway instance with proper permissions
resource "aws_iam_role" "gateway" {
  name = "${var.name}-ec2-sdm-gateway-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  tags = merge(var.tagset, {
    network = "Public"
    class   = "sdminfra"
    }
  )
}

# IAM policy allowing the gateway to access tagged secrets in Secrets Manager
resource "aws_iam_policy" "secrets_manager_policy" {
  name        = "${var.name}-ec2-secrets-manager-policy"
  description = "Allows EC2 instances to read from AWS Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/${var.secretkey}" = "${var.secretvalue}" # Only allows reading secrets with this tag
          }
        }
      }
    ]
  })
}

# Attach the IAM Policy to the Role
resource "aws_iam_role_policy_attachment" "attach_secrets_manager_policy" {
  role       = aws_iam_role.gateway.name
  policy_arn = aws_iam_policy.secrets_manager_policy.arn
}


# Instance Profile to attach to the EC2 instance
resource "aws_iam_instance_profile" "gw_instance_profile" {
  name = "${var.name}-gateway-instance-profile"
  role = aws_iam_role.gateway.name
}

# Create a StrongDM gateway node in the control plane
resource "sdm_node" "gateway" {
  gateway {
    name           = "sdm-${var.name}-lab-gw"       # Gateway name visible in StrongDM
    listen_address = "${aws_eip.gateway.public_dns}:5000"  # Public endpoint for client connections
    bind_address   = "0.0.0.0:5000"                 # Local binding for the gateway service
    tags = merge(var.tagset, {
      network = "Public"
      class   = "sdminfra"
      }
    )
  }
}

# Register the gateway host as an SSH resource in StrongDM for administrative access
resource "sdm_resource" "gateway" {
  ssh {
    name     = "${var.name}-gateway"
    hostname = aws_eip.gateway.public_dns
    username = "ubuntu"
    port     = 22

    tags = merge(var.tagset, {
      network = "Public"
      class   = "sdminfra"
      }
    )

  }
}

# Create an AWS key pair using the StrongDM-generated public key
resource "aws_key_pair" "gateway" {
  key_name   = "${var.name}-gateway-key"
  public_key = sdm_resource.gateway.ssh[0].public_key
}

# Launch the EC2 instance that will run the StrongDM gateway
resource "aws_instance" "gateway" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t2.micro"
  subnet_id                   = coalesce(var.gateway_subnet, one(module.network[*].gateway_subnet))
  user_data_replace_on_change = true
  iam_instance_profile        = aws_iam_instance_profile.gw_instance_profile.name
  vpc_security_group_ids      = [one(module.network[*].public_sg)]
  key_name                    = aws_key_pair.gateway.key_name
  
  # Bootstrap the gateway using the provisioning template
  user_data = templatefile("gw-provision.tpl", {
    sdm_relay_token = sdm_node.gateway.gateway[0].token  # Token for gateway registration
    target_user     = "ubuntu"                           # User to run the gateway service
    sdm_domain      = data.env_var.sdm_api.value == "" ? "" : coalesce(join(".", slice(split(".", element(split(":", data.env_var.sdm_api.value), 0)), 1, length(split(".", element(split(":", data.env_var.sdm_api.value), 0))))), "")
  })

  tags = merge(var.tagset, {
    network = "Public"
    class   = "sdminfra"
    Name    = "sdm-${var.name}-lab-gw"
    }
  )
}

# Associate the Elastic IP with the gateway instance
resource "aws_eip_association" "gw_eip_assoc" {
  instance_id   = aws_instance.gateway.id
  allocation_id = aws_eip.gateway.id
}