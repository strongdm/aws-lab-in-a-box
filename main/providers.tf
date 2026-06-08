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


# AWS Provider - Uses the region variable and standard AWS authentication methods
provider "aws" {
  region = var.region # Region can be specified in terraform.tfvars
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0" # AWS provider v6 (Enhanced Region Support, OpsWorks/SimpleDB/Worklink removed)
    }
    sdm = {
      source  = "strongdm/sdm"
      version = "~> 17.0" # StrongDM provider v17 (MCP Gateway OAuth, MS SQL Kerberos identity aliases)
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.4"
    }
    env = {
      source  = "tcarreira/env"
      version = "~> 0.2"
    }
  }

  required_version = ">= 1.5.0"
}

# Get current AWS region information
data "aws_region" "current" {}

# Get StrongDM API host from environment, used for gateway/relay registration
data "env_var" "sdm_api" {
  id = "SDM_API_HOST"
}
