output "ip" {
    value = aws_instance.hcvault.private_ip
    description = "Private IP address of the Vault instance"
}

output "instance_id" {
    value = aws_instance.hcvault.id
    description = "EC2 instance ID of the Vault server"
}

output "target_user" {
    value = var.target_user
    description = "SSH user for the Vault instance"
}

output "tagset" {
    value = local.thistagset
    description = "Tags applied to Vault resources"
}

output "kms_key_id" {
    value = aws_kms_key.vault_unseal.key_id
    description = "KMS key ID used for Vault auto-unsealing"
}

output "vault_url" {
    value = "http://${aws_instance.hcvault.private_ip}:8200"
    description = "Vault server URL"
}

output "iam_role_arn" {
    value = aws_iam_role.vault.arn
    description = "IAM role ARN for the Vault instance"
}