
terraform {
  required_providers {

    sdm = {
      source  = "strongdm/sdm"
      version = ">=14.20.0" # Requires StrongDM provider v14.13.0+ for all features
    }
  }

  required_version = ">= 1.1.0" # Requires Terraform 1.1.0+
}