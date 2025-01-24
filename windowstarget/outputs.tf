output "windowstarget_fqdn" {
    value = aws_instance.windowstarget.private_dns
}

output "windowstarget_ip" {
    value = aws_instance.windowstarget.private_ip
}

output "windowstarget_username" {
    value = "administrator"
}

output "windowstarget_password" {
    value = rsadecrypt(aws_instance.windowstarget.password_data, var.private_key_pem)
}

output "thistagset" {
    value = local.thistagset
} 