#--------------------------------------------------------------
# EKS Cluster Outputs
#
# These outputs are used by the main module to register the EKS cluster
# with StrongDM as a Kubernetes resource target. They provide the
# necessary information for authentication and connection to the cluster.
#--------------------------------------------------------------

output "name" {
  description = "The name of the EKS cluster, used as identifier in StrongDM"
  value       = aws_eks_cluster.eks.name
}

output "endpoint" {
  description = "The API server endpoint URL for the EKS cluster"
  value       = aws_eks_cluster.eks.endpoint
}

output "ca" {
  description = "Certificate authority data for the EKS cluster, required for secure connection"
  value       = aws_eks_cluster.eks.certificate_authority
}

output "identity" {
  description = "Information about the OIDC identity provider for the cluster"
  value       = aws_eks_cluster.eks.identity
}

output "thistagset" {
  description = "Tags applied to EKS resources, useful for resource organization and StrongDM integration"
  value       = local.thistagset
}

output "cluster_id" {
  description = "EKS cluster identifier"
  value       = aws_eks_cluster.eks.id
}

# Commented out legacy output - keeping for reference
#output "role" {
#  description = "The IAM role ARN for EKS access"
#  value       = aws_iam_role.eks_access_role.arn
#}
