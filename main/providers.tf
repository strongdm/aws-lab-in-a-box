#--------------------------------------------------------------
# Provider Configuration
#
# This file configures the AWS and StrongDM providers needed for
# deploying and managing resources in this lab environment.
#
# Key components:
# - AWS provider for infrastructure deployment
# - StrongDM provider for access control configuration
# - External providers for helper functionality
#--------------------------------------------------------------

# StrongDM Provider - Must be configured via environment variables:
# SDM_API_ACCESS_KEY and SDM_API_SECRET_KEY
provider "sdm" {}

# AWS Provider - Uses the region variable and standard AWS authentication methods
provider "aws" {
  region = var.region # Region can be specified in terraform.tfvars
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0" # Requires AWS provider v5+ for all features
    }
    sdm = {
      source  = "strongdm/sdm"
      version = ">=3.3.0" # Requires StrongDM provider v3.3.0+ for all features
    }
    external = {
      source = "hashicorp/external" # Used for external data sources and commands
    }
    env = {
      source = "tcarreira/env" # Used for accessing environment variables
    }
  }

  required_version = ">= 1.1.0" # Requires Terraform 1.1.0+
}

# Get current AWS region information
data "aws_region" "current" {}

# Get StrongDM API host from environment, used for gateway/relay registration
data "env_var" "sdm_api" {
  id = "SDM_API_HOST"
}