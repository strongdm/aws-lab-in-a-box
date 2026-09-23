#--------------------------------------------------------------
# Domain Controller Readiness Gate
#
# The domain controller installs AD DS, DNS and ADCS through a
# PowerShell sequence with several reboots, creates the scoped
# service accounts, and finally links the group policy that
# disables NLA for certificate-based RDP. Nothing that joins the
# domain or authenticates against it can run before that
# finishes.
#
# The gate waits for the completion marker the install script
# publishes to Parameter Store as its last act. An earlier
# version polled the DC's StrongDM health check instead, which
# passed about two minutes after launch: the base Windows AMI
# answers RDP with NLA from first boot, long before the domain
# exists. That released the Windows target roughly fifteen
# minutes early, so it joined against a server that was still
# promoting and never received the NLA policy, which had not
# been created yet.
#
# Requires the AWS CLI and the credentials Terraform already
# uses. Set dc_ready_timeout to allow for a vanilla AMI, which
# takes appreciably longer than a Packer-built one.
#--------------------------------------------------------------

resource "terraform_data" "dc_ready" {
  # Everything that needs a promoted domain: a Windows target or an ADCS server
  # joining it, and the AD secret engine, whose bind account the install script
  # creates.
  count = (var.create_domain_controller && (var.create_windows_target || var.create_adcs || var.create_managedsecrets || try(var.domain_users, null) != null)) ? 1 : 0

  input = one(module.dc[*].ssm_provisioning_complete_parameter)

  provisioner "local-exec" {
    command = "bash ${path.module}/wait-for-dc.sh ${one(module.dc[*].ssm_provisioning_complete_parameter)} ${data.aws_region.current.region} ${var.dc_ready_timeout}"
  }
}
