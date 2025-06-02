#--------------------------------------------------------------
# AMI Data Sources Configuration
#
# This file defines data sources to locate the latest Amazon Machine Images
# (AMIs) for different operating systems used throughout the lab environment.
# Using dynamic AMI lookups ensures the lab always uses current, secure
# images while maintaining compatibility with the configured instance types.
#
# Components:
# - Ubuntu 22.04 LTS AMI for Linux targets
# - Windows Server AMI for domain controller and Windows targets
# - Dynamic lookup filters for latest stable releases
#--------------------------------------------------------------

# Locate the latest Ubuntu 22.04 LTS AMI for Linux targets
data "aws_ami" "ubuntu" {
  most_recent = true # Always use the most recent version

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"] # Ubuntu 22.04 LTS pattern
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"] # Hardware Virtual Machine for better performance
  }

  owners = ["099720109477"] # Canonical (Ubuntu's official publisher)
}

# Locate the latest Windows Server AMI for domain controller and Windows targets
data "aws_ami" "windows" {
  most_recent = true # Always use the most recent version
  filter {
    name   = "name"
    values = ["Windows_Server-2019-English-Full-Base-*"] # Windows Server 2019 Full Base
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"] # Hardware Virtual Machine for better performance
  }
  owners = ["801119661308"] # Amazon (official Windows AMI publisher)
}