# Amazon EKS Module for StrongDM Lab

## Overview

This module creates an Amazon Elastic Kubernetes Service (EKS) cluster that serves as a Kubernetes target for StrongDM access control demonstrations. It establishes a secure, managed Kubernetes environment that can be accessed through StrongDM's access workflow.

## Architecture

The module provisions:
- An EKS cluster running Kubernetes version 1.31
- IAM roles and policies for cluster operation
- Node pools for running workloads
- Access policies for secure authentication
- Integration with StrongDM for controlled access

## Use Cases for Partner Training

1. **Container Orchestration Access**: Demonstrate how StrongDM can manage access to Kubernetes clusters
2. **Kubectl Command Access**: Show controlled kubectl access through StrongDM's access workflow
3. **DevOps Access Control**: Illustrate how StrongDM can provide temporary access to K8s resources
4. **Infrastructure as Code**: Showcase automated deployment of cloud resources with proper access controls

## Configuration

### Basic Usage

```hcl
module "eks" {
  source    = "../eks"
  name      = var.name
  subnet_id = [subnet-1, subnet-2, subnet-3]
  tagset    = var.tagset
  role      = aws_iam_role.gateway.arn
}
```

### Required Variables

- `subnet_id`: List of subnet IDs for the EKS cluster deployment (multi-AZ for high availability)
- `tagset`: Tags to apply to all EKS resources
- `name`: Name prefix for all resources
- `role`: ARN of the role that will be allowed to access the EKS cluster (typically the gateway role)

## Integration with StrongDM

The module outputs all necessary information to register the EKS cluster with StrongDM:
- Cluster name
- Endpoint for API server access
- Certificate authority data for authentication
- Node role ARN

The main module's `eks-target.tf` file demonstrates how to create a StrongDM resource using this module's outputs.

## Best Practices

For production environments (unlike this demo):
- Use managed node groups with appropriate instance types based on workload requirements
- Implement cluster autoscaling for dynamic resource allocation
- Configure Network Policies for pod-to-pod communication security 
- Set up proper RBAC (Role-Based Access Control) within the cluster
- Enable control plane logging and monitoring
- Use private endpoint access for enhanced security

## Additional Resources

- [EKS Sample Application](../eks-sample-app/): Contains example Kubernetes manifests for deploying a sample application to test the EKS cluster
- [AWS EKS Documentation](https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html)
- [StrongDM Kubernetes Integration](https://www.strongdm.com/docs/admin/guides/kubernetes)