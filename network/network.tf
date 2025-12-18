#--------------------------------------------------------------
# AWS Network Infrastructure Module
#
# This module creates the foundational networking components needed for the 
# StrongDM lab environment. The network infrastructure follows AWS best practices
# with a public subnet for internet-facing components and private subnets for 
# protected resources.
#
# Components:
# - VPC with DNS support
# - Public subnet for the StrongDM Gateway
# - Private subnets for target resources (databases, servers, etc.)
# - Internet Gateway for public subnet internet access
# - NAT Gateway for private subnet internet access
# - Security Groups with appropriate ingress/egress rules
# - Route tables configured for proper network isolation
#--------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = merge(var.tagset, {
    network = "Public"
    Name    = "${var.name}-vpc"
  })
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "gateway" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.254.0/24"

  tags = merge(var.tagset, {
    network = "Public"
    Name    = "${var.name}-public-subnet"

  })
}
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "relay" {
  count      = length(data.aws_availability_zones.available.names)
  vpc_id     = aws_vpc.main.id
  cidr_block = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)

  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-subnet"

  })
}

resource "aws_eip" "public" {
  domain = "vpc"

  tags = merge(var.tagset, {
    network = "Public"
    class   = "sdminfra"
    }
  )
}

resource "aws_nat_gateway" "gateway" {
  subnet_id     = aws_subnet.gateway.id
  allocation_id = aws_eip.public.id

  tags = merge(var.tagset, {
    network = "Public"
    Name    = "${var.name}-public-nat"

  })

}

resource "aws_security_group" "gateway" {
  name   = "${var.name}-public-sg"
  vpc_id = aws_vpc.main.id
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = merge(var.tagset, {
    network = "Public"
    Name    = "${var.name}-public-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_ssh_gateway" {
  security_group_id = aws_security_group.gateway.id
  from_port         = 22
  ip_protocol       = "tcp"
  to_port           = 22
  cidr_ipv4         = "0.0.0.0/0"


  tags = merge(var.tagset, {

    network = "Public"
    Name    = "${var.name}-Public-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_icmp" {
  security_group_id = aws_security_group.gateway.id
  ip_protocol       = "icmp"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = -1
  to_port           = -1


  tags = merge(var.tagset, {
    network = "Public"
    Name    = "${var.name}-Public-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_strongdm_gateway" {
  security_group_id = aws_security_group.gateway.id
  from_port         = 5000
  ip_protocol       = "tcp"
  to_port           = 5000
  cidr_ipv4         = "0.0.0.0/0"
  tags = merge(var.tagset, {
    network = "Public"
    Name    = "${var.name}-Public-sg"
  })
}



resource "aws_security_group" "relay" {
  name   = "${var.name}-private-sg"
  vpc_id = aws_vpc.main.id
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_icmp_relay" {
  security_group_id = aws_security_group.relay.id
  ip_protocol       = "icmp"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = -1
  to_port           = -1


  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-Private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_postgresql" {
  count             = var.create_rds_postgresql ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 5432
  ip_protocol       = "tcp"
  to_port           = 5432

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_documentdb" {
  count             = var.create_docdb ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 27017
  ip_protocol       = "tcp"
  to_port           = 27017

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_windows" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 3389
  ip_protocol       = "tcp"
  to_port           = 3389

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_kpasswd" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 464
  ip_protocol       = "tcp"
  to_port           = 464

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}


resource "aws_vpc_security_group_ingress_rule" "allow_hcvault" {
  count             = var.create_hcvault ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 8200
  ip_protocol       = "tcp"
  to_port           = 8200
  
  tags = merge (var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_dns_udp" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 53
  ip_protocol       = "udp"
  to_port           = 53

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_dns_tcp" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 53
  ip_protocol       = "tcp"
  to_port           = 53

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_ldap_udp" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 389
  ip_protocol       = "udp"
  to_port           = 389

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_ldap_tcp" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 389
  ip_protocol       = "tcp"
  to_port           = 389

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

# Global Catalog ports (3268/3269) - Required for SSSD enumeration on Linux targets
# These ports allow domain-joined Linux machines to enumerate AD groups and resolve
# group names instead of showing numeric GIDs
resource "aws_vpc_security_group_ingress_rule" "allow_gc_tcp" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 3268
  ip_protocol       = "tcp"
  to_port           = 3269

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_ldaps_tcp" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 636
  ip_protocol       = "tcp"
  to_port           = 636

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_ldaps_udp" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 636
  ip_protocol       = "udp"
  to_port           = 636

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}


resource "aws_vpc_security_group_ingress_rule" "allow_krb_tcp" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 88
  ip_protocol       = "tcp"
  to_port           = 88

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_rpc_tcp" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 135
  ip_protocol       = "tcp"
  to_port           = 135

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_netbios_tcp" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 139
  ip_protocol       = "tcp"
  to_port           = 139

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_ssl_tcp" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443

  tags = merge (var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_smb_tcp" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 445
  ip_protocol       = "tcp"
  to_port           = 445

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_ad_tcp" {
  count             = var.create_windows_target || var.create_domain_controller ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 49152
  ip_protocol       = "tcp"
  to_port           = 65535

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_linux" {
  count             = var.create_linux_target ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 22
  ip_protocol       = "tcp"
  to_port           = 22

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "allow_https" {
  count             = var.create_eks ? 1 : 0
  security_group_id = aws_security_group.relay.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443

  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-private-sg"
  })
}

resource "aws_default_route_table" "main" {
  default_route_table_id = aws_vpc.main.default_route_table_id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }


  tags = merge(var.tagset, {
    network = "Private"
    Name    = "${var.name}-route-table"
  })
}
resource "aws_route_table_association" "main" {
  subnet_id      = aws_subnet.gateway.id
  route_table_id = aws_default_route_table.main.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.gateway.id
  }

  tags = {
    Name = "Private Route Table"
  }
}

# Associate the private route table with the private subnet
resource "aws_route_table_association" "private_association" {
  count          = length(aws_subnet.relay[*].id)
  subnet_id      = element(aws_subnet.relay[*].id, count.index)
  route_table_id = aws_route_table.private.id
}
