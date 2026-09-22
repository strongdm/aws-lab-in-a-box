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
  # Every StrongDM resource this lab can register. compact() drops the ones
  # whose feature flag is off, and the health check runs once per remaining ID
  # because the CLI rejects a name pattern matching more than one resource.
  healthcheck_resource_ids = compact([
    sdm_resource.gateway.id,
    sdm_resource.relay.id,
    one(sdm_resource.ssh-ca-target[*].id),
    one(sdm_resource.rds-psql-target[*].id),
    one(sdm_resource.docdb-target[*].id),
    one(sdm_resource.eks[*].id),
    one(sdm_resource.dc[*].id),
    one(sdm_resource.windows-target[*].id),
    one(sdm_resource.windows-target-rdp[*].id),
    one(sdm_resource.ssh-hcvault[*].id),
    one(sdm_resource.awsrocli[*].id),
    one(sdm_resource.awsroconsole[*].id),
    one(sdm_resource.awss3fullcli[*].id),
    one(sdm_resource.awss3fullconsole[*].id),
    one(sdm_resource.awss3rocli[*].id),
    one(sdm_resource.awss3webconsole[*].id),
    one(sdm_resource.awsgluefullcli[*].id),
    one(sdm_resource.awsglefullconsole[*].id),
  ])
}

# One check per resource. A target that is still booting stays unhealthy until
# it is checked again, so re-run with
# terraform apply -replace='terraform_data.healthcheck["rs-..."]' or wait for
# StrongDM's own scheduled check.
resource "terraform_data" "healthcheck" {
  for_each = var.run_healthchecks == false ? toset([]) : toset(local.healthcheck_resource_ids)

  input = each.value

  provisioner "local-exec" {
    command = "sdm admin resources healthcheck ${each.value}"
  }
}
