
#--------------------------------------------------------------
# Secrets Management Module Provider Configuration
#
# This file configures the StrongDM provider specifically for the secrets
# management module. It ensures compatibility with the required StrongDM
# features for managed secrets and secret engines.
#
# Components:
# - StrongDM provider with managed secrets support
# - Version constraints for feature compatibility
#--------------------------------------------------------------

terraform {
  required_providers {

    sdm = {
      source  = "strongdm/sdm"
      version = ">=14.20.0" # Requires StrongDM provider v14.20.0+ for managed secrets features
    }
  }

  required_version = ">= 1.1.0" # Requires Terraform 1.1.0+ for modern provider features
}