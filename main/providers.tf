provider "sdm" {}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
    }
   sdm = {
      source = "strongdm/sdm"
      version = ">=3.3.0"
    }
   external = {
     source = "hashicorp/external"
   }
    env = {
      source = "tcarreira/env"
    }
  }

  required_version = ">= 1.1.0"
}

data "aws_region" "current" {}

data "env_var" "sdm_api" {
  id = "SDM_API_HOST"
}