module "eks" {
    count  = var.create_eks == false ? 0 : 1
    source = "../eks"
    name       = var.name
    subnet_id  = [coalesce(var.relay_subnet,one(module.network[*].relay_subnet)),coalesce(var.relay_subnet-b,one(module.network[*].relay_subnet-b)),coalesce(var.relay_subnet-c,one(module.network[*].relay_subnet-c))]
    tagset     = var.tagset
    role       = aws_iam_role.gateway.arn
}

resource "sdm_resource" "eks" {
    count  = var.create_eks == false ? 0 : 1
    amazon_eks_instance_profile {
        certificate_authority = base64decode(module.eks[0].ca[0].data)
        endpoint = module.eks[0].endpoint
        name = "eks-cluster"
        cluster_name = module.eks[0].name
        region = data.aws_region.current.name
        tags = module.eks[0].thistagset
    }

}