#--------------------------------------------------------------
# RDS PostgreSQL Module Outputs
#
# These outputs provide the necessary information for integrating the
# PostgreSQL database with StrongDM. They expose connection details, 
# credentials, and metadata used when registering the database as a 
# StrongDM resource.
#--------------------------------------------------------------

output "target_hostname" {
  value       = aws_db_instance.rds_target.address
  description = "Endpoint hostname for connecting to the PostgreSQL instance"
}

output "target_port" {
  value       = aws_db_instance.rds_target.port
  description = "Port number for connecting to the PostgreSQL instance (typically 5432)"
}

output "secret_arn" {
  value       = aws_db_instance.rds_target.master_user_secret[0].secret_arn
  description = "ARN of the AWS Secrets Manager secret containing database credentials"
}

output "db_name" {
  value       = aws_db_instance.rds_target.db_name
  description = "Name of the PostgreSQL database created in the instance"
}

output "thistagset" {
  value       = local.thistagset
  description = "Tags applied to the PostgreSQL instance, used for consistent resource management"
}

output "instance_id" {
  value       = aws_db_instance.rds_target.id
  description = "RDS instance identifier"
}