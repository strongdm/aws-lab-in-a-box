
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
      version = "~> 17.0" # StrongDM provider v17 for managed secrets features
    }
  }

  required_version = ">= 1.5.0"
}