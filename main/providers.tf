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
  }

  required_version = ">= 1.1.0"
}

data "aws_region" "current" {}