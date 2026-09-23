#--------------------------------------------------------------
# Post-deployment Health Checks
#
# StrongDM records a resource's health when it is registered,
# which is usually before the target has finished booting. The
# result is a lab that shows unhealthy targets until StrongDM's
# next scheduled check catches up.
#
# Setting run_healthchecks asks StrongDM to re-check every
# resource this lab registered, once the resource exists.
#
# Requires the sdm CLI on PATH. It authenticates with the same
# SDM_API_ACCESS_KEY and SDM_API_SECRET_KEY the provider uses, so
# no extra credentials are needed.
#--------------------------------------------------------------

locals {
  # Keyed by target name rather than resource ID: for_each keys must be known
  # at plan time, and an ID is only known after the resource is created. The
  # feature flags decide which keys exist, so the map stays plan-time complete
  # while the IDs themselves resolve during apply.
  healthcheck_resources = merge(
    {
      gateway = sdm_resource.gateway.id
      relay   = sdm_resource.relay.id
    },
    var.create_linux_target ? { linux = one(sdm_resource.ssh-ca-target[*].id) } : {},
    var.create_rds_postgresql ? { postgresql = one(sdm_resource.rds-psql-target[*].id) } : {},
    var.create_docdb ? { documentdb = one(sdm_resource.docdb-target[*].id) } : {},
    var.create_eks ? { eks = one(sdm_resource.eks[*].id) } : {},
    var.create_domain_controller ? { domain_controller = one(sdm_resource.dc[*].id) } : {},
    var.create_adcs ? { adcs = one(sdm_resource.adcs[*].id) } : {},
    var.create_windows_target ? {
      windows_target = one(sdm_resource.windows-target[*].id)
      windows_rdp    = one(sdm_resource.windows-target-rdp[*].id)
    } : {},
    var.create_hcvault ? { hcvault = one(sdm_resource.ssh-hcvault[*].id) } : {},
    var.create_aws_ro ? {
      aws_cli_ro     = one(sdm_resource.awsrocli[*].id)
      aws_console_ro = one(sdm_resource.awsroconsole[*].id)
    } : {},
    var.create_aws_s3full ? {
      s3_cli_full     = one(sdm_resource.awss3fullcli[*].id)
      s3_console_full = one(sdm_resource.awss3fullconsole[*].id)
    } : {},
    var.create_aws_s3ro ? {
      s3_cli_ro     = one(sdm_resource.awss3rocli[*].id)
      s3_console_ro = one(sdm_resource.awss3webconsole[*].id)
    } : {},
    var.create_aws_gluefull ? {
      glue_cli_full     = one(sdm_resource.awsgluefullcli[*].id)
      glue_console_full = one(sdm_resource.awsglefullconsole[*].id)
    } : {},
  )
}

# One check per resource, because the CLI rejects a name pattern that matches
# more than one. A target that was still booting stays unhealthy until it is
# checked again, so re-run a single check with
# terraform apply -replace='terraform_data.healthcheck["postgresql"]'
resource "terraform_data" "healthcheck" {
  for_each = var.run_healthchecks == false ? {} : local.healthcheck_resources

  input = each.value

  provisioner "local-exec" {
    command = "sdm admin resources healthcheck ${each.value}"
  }
}
