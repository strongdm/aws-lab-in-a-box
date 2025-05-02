#-------------------------------------------------------
# DocumentDB Password Management
#
# This file handles the generation of a secure password
# for the DocumentDB cluster when one isn't explicitly 
# provided through the variables.
#
# In production environments, consider using AWS Secrets 
# Manager directly to store and rotate credentials.
#-------------------------------------------------------

# Generate a random password for DocumentDB if not provided
# This creates a secure 16-character password when var.password is null
resource "random_password" "docdb_password" {
  count   = var.password == null ? 1 : 0
  length  = 16
  special = false     # Avoiding special characters for better compatibility
}

locals {
  # Use provided password or generated one
  # This approach allows either manual password specification or automatic generation
  actual_password = var.password == null ? random_password.docdb_password[0].result : var.password
}