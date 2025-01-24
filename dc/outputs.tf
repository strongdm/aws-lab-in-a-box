output "dc_fqdn" {
    value = aws_instance.dc.private_dns
}

output "dc_ip" {
    value = aws_instance.dc.private_ip
}

output "dc_username" {
    value = "administrator"
}

output "dc_password" {
    value = rsadecrypt(aws_instance.dc.password_data, tls_private_key.windows.private_key_pem)
}

output "domain_admin" {
    value = "domainadmin"
}

output "domain_password" {
    value = "${random_password.admin_password.result}!"
}

output "thistagset" {
    value = local.thistagset
} 

output "private_key_pem" {
    value = tls_private_key.windows.private_key_pem
}

output "key_name" {
    value = aws_key_pair.windows.key_name
}