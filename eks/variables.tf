#--------------------------------------------------------------
# EKS Module Variables
#
# This file defines the input variables required to configure the EKS
# cluster. These variables are used to customize the deployment based on
# the network configuration, naming standards, and integration with
# StrongDM.
#--------------------------------------------------------------

variable "subnet_id" {
  description = "List of subnet IDs in which to deploy the EKS cluster. Should be at least two subnets in different availability zones for high availability."
  type        = list(string)
  default     = null
}

variable "tagset" {
  description = "Map of tags to apply to all StrongDM and EKS resources. Used for resource organization and identification in AWS console."
  type        = map(string)
}

variable "name" {
  description = "Name prefix to add to all created resources. Used to identify resources belonging to this deployment."
  type        = string
}

variable "role" {
  description = "IAM role ARN to associate with the EKS cluster. This role will be granted admin permissions to the cluster through StrongDM."
  type        = string
}

locals {
  # Merge provided tags with EKS-specific tags to ensure proper classification
  thistagset = merge(var.tagset, {
    network = "Private" # Indicates this resource belongs to a private network
    class   = "target"  # Identifies this resource as a target for StrongDM
  })
}