#--------------------------------------------------------------
# Windows Target Module Outputs
#
# These outputs provide the necessary information for integrating the
# Windows server with StrongDM. They expose connection details, credentials,
# and metadata used when registering the Windows target as a StrongDM resource.
#--------------------------------------------------------------

output "windowstarget_fqdn" {
    value = aws_instance.windowstarget.private_dns
    description = "Private DNS name of the Windows target for RDP connections"
}

output "windowstarget_ip" {
    value = aws_instance.windowstarget.private_ip
    description = "Private IP address of the Windows target for RDP connections"
}

output "windowstarget_username" {
    value = "administrator"
    description = "Default administrator username for RDP connections"
}

output "windowstarget_password" {
    value = rsadecrypt(aws_instance.windowstarget.password_data, var.private_key_pem)
    description = "Decrypted administrator password for RDP connections"
    sensitive = true
}

output "thistagset" {
    value = local.thistagset
    description = "Tags applied to the Windows target, used for consistent resource management"
}