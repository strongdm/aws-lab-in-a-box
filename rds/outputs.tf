output "target_hostname" {
    value = aws_db_instance.rds_target.address
}

output "target_port" {
    value = aws_db_instance.rds_target.port
}

output "secret_arn" {
    value = aws_db_instance.rds_target.master_user_secret[0].secret_arn
}

output "db_name" {
    value = aws_db_instance.rds_target.db_name
}

output "thistagset" {
    value = local.thistagset
} 