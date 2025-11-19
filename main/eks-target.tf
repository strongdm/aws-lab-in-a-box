#--------------------------------------------------------------
# Amazon EKS (Kubernetes) Target Configuration
#
# This file creates an Amazon Elastic Kubernetes Service (EKS) cluster
# and registers it with StrongDM for secure Kubernetes access. The EKS
# target demonstrates how StrongDM can provide controlled access to 
# container orchestration platforms.
#
# Components:
# - Amazon EKS cluster in a private subnet
# - IAM role and permissions configuration
# - StrongDM resource registration for Kubernetes access
#--------------------------------------------------------------

# Create the EKS cluster using the eks module
module "eks" {
  count  = var.create_eks == false ? 0 : 1 # Conditionally create based on feature flag
  source = "../eks"                        # Reference to the EKS module
  name   = var.name                        # Name prefix for resources

  # Use subnets across multiple availability zones for high availability
  subnet_id = [coalesce(var.relay_subnet, one(module.network[*].relay_subnet)),
    coalesce(var.relay_subnet-b, one(module.network[*].relay_subnet-b)),
  coalesce(var.relay_subnet-c, one(module.network[*].relay_subnet-c))]

  tagset = var.tagset               # Tags for resource identification
  role   = aws_iam_role.gateway.arn # Gateway role ARN for EKS access
}

# Register the EKS cluster as a Kubernetes resource in StrongDM
resource "sdm_resource" "eks" {
  count = var.create_eks == false ? 0 : 1
  amazon_eks_instance_profile {
    certificate_authority = base64decode(module.eks[0].ca[0].data) # Cluster CA certificate
    endpoint              = module.eks[0].endpoint                 # Kubernetes API endpoint
    name                  = "${var.name}-eks-cluster"              # Resource name in StrongDM
    cluster_name          = module.eks[0].name                     # EKS cluster name
    region                = data.aws_region.current.name           # AWS region
    tags                  = merge(module.eks[0].thistagset, {
      sdm__cloud_id = module.eks[0].cluster_id
    })
  }
}