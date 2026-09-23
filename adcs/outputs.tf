#--------------------------------------------------------------
# ADCS/NDES Module Outputs
#
# Exports essential information about the ADCS/NDES server for
# integration with StrongDM and other infrastructure components.
#--------------------------------------------------------------

output "adcs_instance_id" {
  description = "EC2 instance ID of the ADCS/NDES server"
  value       = aws_instance.adcs.id
}

output "adcs_private_ip" {
  description = "Private IP address of the ADCS/NDES server"
  value       = aws_instance.adcs.private_ip
}

output "adcs_hostname" {
  description = "Hostname of the ADCS/NDES server"
  value       = aws_instance.adcs.private_dns
}

output "adcs_fqdn" {
  description = "Fully qualified domain name of the ADCS server"
  value       = local.server_fqdn
}

output "ndes_url" {
  description = "NDES enrollment URL for StrongDM gateway configuration (HTTPS)"
  value       = "https://${local.server_fqdn}/certsrv/mscep/mscep.dll"
}

output "server_url" {
  description = "Base server URL for StrongDM Active Directory secret store (HTTPS)"
  value       = "https://${local.server_fqdn}/"
}

output "ca_common_name" {
  description = "Common Name of the intermediate CA"
  value       = local.ca_common_name
}

output "certificate_template_name" {
  description = "Name of the StrongDM certificate template"
  value       = var.certificate_template_name
}

output "sdm_adcs_user" {
  description = "Username for SDM_ADCS_USER gateway configuration (scoped relay account)"
  value       = "svc-sdm-relay@${local.domain_fqdn}"
}

output "sdm_adcs_password" {
  description = "Password for SDM_ADCS_PW gateway configuration (scoped relay account)"
  value       = var.svc_relay_password
  sensitive   = true
}

output "domain_admin_user" {
  description = "DEPRECATED: Use sdm_adcs_user instead. Domain administrator username."
  value       = "${var.domain_admin_user}@${local.domain_fqdn}"
}

output "tagset" {
  description = "Tags applied to the ADCS/NDES resources"
  value       = local.thistagset
}

output "admin_username" {
  description = "Local administrator username for RDP access"
  value       = "Administrator"
}

output "admin_password" {
  description = "Decrypted password for the local administrator account, or null when private_key_pem was not provided"
  value       = var.private_key_pem == null ? null : rsadecrypt(aws_instance.adcs.password_data, var.private_key_pem)
  sensitive   = true
}
