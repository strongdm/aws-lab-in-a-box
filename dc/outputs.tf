#--------------------------------------------------------------
# Domain Controller Module Outputs
#
# These outputs expose important information about the domain controller
# for use by other modules, particularly for configuring Windows targets
# and StrongDM resources that need domain authentication.
#--------------------------------------------------------------

# Network information for accessing the domain controller
output "dc_fqdn" {
  value       = aws_instance.dc.private_dns
  description = "The private DNS name of the domain controller"
}

output "dc_ip" {
  value       = aws_instance.dc.private_ip
  description = "The private IP address of the domain controller"
}

# Administrator account credentials for direct RDP access
output "dc_username" {
  value       = "administrator"
  description = "The local administrator username for the domain controller"
}

output "dc_password" {
  value       = rsadecrypt(aws_instance.dc.password_data, tls_private_key.windows.private_key_pem)
  description = "The decrypted password for the local administrator account"
  sensitive   = true
}

# Domain administrator credentials for domain operations
output "domain_admin" {
  value       = "domainadmin"
  description = "The domain administrator username created during setup"
}

output "domain_password" {
  value       = "${random_password.admin_password.result}!"
  description = "The password for the domain administrator account"
  sensitive   = true
}

# Resource tags for consistent resource management
output "thistagset" {
  value       = local.thistagset
  description = "The tags applied to resources in this module"
}

# Key material for other resources that need to join the domain
output "private_key_pem" {
  value       = tls_private_key.windows.private_key_pem
  description = "The private key in PEM format for decrypting Windows passwords"
  sensitive   = true
}

output "key_name" {
  value       = aws_key_pair.windows.key_name
  description = "The name of the key pair created for Windows instances"
}