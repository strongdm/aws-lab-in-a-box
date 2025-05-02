module "network" {
  count  = var.vpc == null ? 1 : 0
  source = "../network"

  vpc                      = var.vpc
  create_eks               = var.create_eks
  create_rds_postgresql    = var.create_rds_postgresql
  create_docdb             = var.create_docdb
  create_domain_controller = var.create_domain_controller
  create_windows_target    = var.create_windows_target
  create_linux_target      = var.create_linux_target
  tagset                   = var.tagset
  name                     = var.name
}