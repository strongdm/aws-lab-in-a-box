#--------------------------------------------------------------
# Network Configuration
#
# This file configures the networking infrastructure for the StrongDM lab
# environment using the network module. It creates a VPC with public and
# private subnets, security groups, and appropriate routing if they don't
# already exist.
#
# The network is a critical foundation that enables secure separation
# between internet-facing resources (gateway) and protected resources.
#--------------------------------------------------------------

# Create the network infrastructure using the network module
module "network" {
  count  = var.vpc == null ? 1 : 0 # Only create if not using an existing VPC
  source = "../network"            # Reference to the network module

  # Pass through all feature flags to determine necessary security group rules
  vpc                      = var.vpc
  create_eks               = var.create_eks
  create_rds_postgresql    = var.create_rds_postgresql
  create_docdb             = var.create_docdb
  create_domain_controller = var.create_domain_controller
  create_windows_target    = var.create_windows_target
  create_linux_target      = var.create_linux_target
  create_hcvault           = var.create_hcvault
  tagset                   = var.tagset
  name                     = var.name
}