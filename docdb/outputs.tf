#--------------------------------------------------------------
# DocumentDB Module Outputs
#
# This file defines the output values from the DocumentDB module that other
# modules and resources need to reference. These outputs provide connection
# endpoints, credentials, and resource identifiers needed for StrongDM
# integration and database access configuration.
#--------------------------------------------------------------

output "docdb_endpoint" {
  description = "Endpoint for the DocumentDB cluster (writer instance)"
  value       = aws_docdb_cluster.docdb_cluster.endpoint
}

output "docdb_reader_endpoint" {
  description = "Reader endpoint for the DocumentDB cluster (for read-only operations)"
  value       = aws_docdb_cluster.docdb_cluster.reader_endpoint
}

output "docdb_port" {
  description = "Port for the DocumentDB cluster (default: 27017 for MongoDB compatibility)"
  value       = 27017
}

output "docdb_username" {
  description = "Username for the DocumentDB cluster (admin user)"
  value       = var.username
}

output "docdb_password" {
  description = "Password for the DocumentDB cluster (auto-generated or user-provided)"
  value       = local.actual_password
  sensitive   = true # Marked as sensitive to prevent exposure in logs
}

output "thistagset" {
  description = "Tags applied to DocumentDB resources (used by StrongDM resource definitions)"
  value       = local.thistagset
}