#--------------------------------------------------------------
# AWS Secrets Manager Store Configuration
#
# This file creates a StrongDM secret store backed by AWS Secrets Manager.
# The secret store serves as the backing storage for StrongDM's secrets
# management capabilities, providing secure storage and retrieval of
# database credentials, API keys, and other sensitive information.
#
# Components:
# - AWS Secrets Manager secret store integration
# - Regional configuration for optimal performance
# - Foundation for managed secrets and credential rotation
#--------------------------------------------------------------

# Create a StrongDM secret store backed by AWS Secrets Manager
resource "sdm_secret_store" "awssecretsmanager" {
  aws {
    name   = "${var.name}awssecretsmanager" # Unique name for the secret store
    region = data.aws_region.current.name   # Use current AWS region for optimal performance
  }
}