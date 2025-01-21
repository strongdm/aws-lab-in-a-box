output "target_hostname" {
    value = aws_instance.ssh-target.private_ip
}

output "target_username" {
    value = var.target_user
}

output "thistagset" {
    value = local.thistagset
} 