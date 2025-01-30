output "name" {
    value = aws_eks_cluster.eks.name
}

output "ca" {
    value = aws_eks_cluster.eks.certificate_authority
}

#output "role" {
#    value = aws_iam_role.eks_access_role.arn
#}

output "endpoint" {
    value = aws_eks_cluster.eks.endpoint
}
output "identity" {
    value = aws_eks_cluster.eks.identity
}

output "thistagset" {
    value = local.thistagset
}
