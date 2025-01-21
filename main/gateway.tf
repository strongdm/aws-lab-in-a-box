resource "aws_eip" "gateway" {
  domain = "vpc"

  tags = merge (var.tagset, {
    network = "Public"
    class   = "sdminfra"
    }
  )
}

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
  tags = merge (var.tagset, {
    network = "Public"
    class   = "sdminfra"
    }
  )
}

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
#        Condition = {
#          StringEquals = {
#            "aws:RequestTag/Environment" = "sdmlab"  # Only allows reading secrets with this tag
#          }
#        }
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

resource "sdm_node" "gateway" {
    gateway {
        name = "sdm-${var.name}-lab-gw"
        listen_address = "${aws_eip.gateway.public_dns}:5000"
        bind_address = "0.0.0.0:5000"
        tags = merge (var.tagset, {
          network = "Public"
          class   = "sdminfra"
          }
        )
    }
}

resource "sdm_resource" "gateway" {
    ssh {
        name     = "${var.name}-gateway"
        hostname = aws_eip.gateway.public_dns
        username = "ubuntu"
        port     = 22
        
        tags = merge (var.tagset, {
          network = "Public"
          class   = "sdminfra"
          }
        )

    }
}

resource "aws_key_pair" "gateway" {
  key_name   = "${var.name}-gateway-key"
  public_key = sdm_resource.gateway.ssh[0].public_key
}

resource "aws_instance" "gateway" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t2.micro"
  subnet_id                   = coalesce(var.gateway_subnet,one(module.network[*].gateway_subnet))
  user_data_replace_on_change = true
  iam_instance_profile        = aws_iam_instance_profile.gw_instance_profile.name
  vpc_security_group_ids      = [one(module.network[*].public_sg)]
  key_name  = aws_key_pair.gateway.key_name
  user_data = templatefile("gw-provision.tpl", {
    sdm_relay_token    = sdm_node.gateway.gateway[0].token
    target_user        = "ubuntu"
  })

    tags = merge (var.tagset, {
    network = "Public"
    class   = "sdminfra"
    Name    = "sdm-${var.name}-lab-gw"
    }
  )
}

resource "aws_eip_association" "gw_eip_assoc" {
  instance_id   = aws_instance.gateway.id
  allocation_id = aws_eip.gateway.id
}