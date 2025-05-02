#--------------------------------------------------------------
# Amazon EKS Cluster Configuration
#
# This file defines the Amazon Elastic Kubernetes Service (EKS) cluster
# and its associated resources. It configures:
# - The core EKS cluster with API access and version settings
# - Compute configuration for running workloads
# - Storage and networking options
# - Access policies for StrongDM integration
#
# The resulting cluster can be registered in StrongDM as a target resource
# for secure access management.
#--------------------------------------------------------------

# Create the primary EKS cluster resource
resource "aws_eks_cluster" "eks" {
  name = "${var.name}-cluster"

  # Configure authentication to use API server auth mode
  access_config {
    authentication_mode = "API"
  }

  # Associate with the cluster IAM role
  role_arn = aws_iam_role.cluster.arn
  
  # Set the Kubernetes version to use
  version  = "1.31"

  # Disable self-managed add-ons - we'll use AWS managed add-ons instead
  bootstrap_self_managed_addons = false

  # Configure compute nodes for the cluster
  compute_config {
    enabled       = true
    node_pools    = ["general-purpose"]  # Use general purpose node pools
    node_role_arn = aws_iam_role.node.arn
  }

  # Configure networking settings for the cluster
  kubernetes_network_config {
    elastic_load_balancing {
      enabled = true  # Enable AWS load balancer integration
    }
  }

  # Configure persistent storage options
  storage_config {
    block_storage {
      enabled = true  # Enable EBS (Elastic Block Store) integration
    }
  }

  # Configure VPC networking for the cluster
  vpc_config {
    endpoint_public_access  = true  # Allow public API endpoint access
    subnet_ids = var.subnet_id     # Use the provided subnets
  }

  # Ensure that IAM Role permissions are created before and deleted
  # after EKS Cluster handling. Otherwise, EKS will not be able to
  # properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.cluster_AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.cluster_AmazonEKSComputePolicy,
    aws_iam_role_policy_attachment.cluster_AmazonEKSBlockStoragePolicy,
    aws_iam_role_policy_attachment.cluster_AmazonEKSLoadBalancingPolicy,
    aws_iam_role_policy_attachment.cluster_AmazonEKSNetworkingPolicy,
  ]
  
  tags = local.thistagset
}

# Associate an admin policy with the provided role (typically the StrongDM gateway role)
# This allows the role to have administrative access to the cluster through StrongDM
resource "aws_eks_access_policy_association" "eks-ro" {
  cluster_name  = aws_eks_cluster.eks.name
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy"
  principal_arn = aws_eks_access_entry.eks-ro.principal_arn

  # Scope the access to the entire cluster
  access_scope {
    type       = "cluster"
  }
}

# Create an access entry for the provided role
# This registers the role as a principal that can access the cluster
resource "aws_eks_access_entry" "eks-ro" {
  cluster_name      = aws_eks_cluster.eks.name
  principal_arn     = var.role  # Use the role ARN provided to the module
}