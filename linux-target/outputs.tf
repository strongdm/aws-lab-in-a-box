#--------------------------------------------------------------
# Linux Target Module Outputs
#
# These outputs provide the necessary information for integrating the
# Linux target with StrongDM. They expose connection details and
# metadata used when registering the target as a StrongDM resource.
#--------------------------------------------------------------

output "target_hostname" {
  value       = aws_instance.ssh-target.private_ip
  description = "Private IP address of the Linux target for SSH connections"
}

output "target_username" {
  value       = var.target_user
  description = "Username to use for SSH connections via StrongDM"
}

output "thistagset" {
  value       = local.thistagset
  description = "Tags applied to the Linux target, used for consistent resource management"
}