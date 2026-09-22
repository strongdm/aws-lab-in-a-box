#--------------------------------------------------------------
# Domain Controller Readiness Gate
#
# The domain controller installs AD, DNS and ADCS through a
# PowerShell sequence with several reboots, and a Windows target
# cannot join the domain until that finishes. Deploying both in
# one apply used to mean the Windows target raced the DC, which
# is why the two were documented as separate applies.
#
# This gate blocks the Windows target until StrongDM reports the
# domain controller as reachable. Its health check is a genuine
# readiness signal because the DC script only re-enables NLA at
# the very end of the sequence.
#
# Requires the sdm CLI and jq on PATH. Without them the wait
# fails fast with a clear message, and the two-apply route still
# works: deploy the DC first, then the Windows target.
#--------------------------------------------------------------

resource "terraform_data" "dc_ready" {
  count = (var.create_domain_controller && var.create_windows_target) ? 1 : 0

  input = one(sdm_resource.dc[*].id)

  provisioner "local-exec" {
    command = "bash ${path.module}/wait-for-dc.sh ${one(sdm_resource.dc[*].id)} ${var.dc_ready_timeout}"
  }
}
