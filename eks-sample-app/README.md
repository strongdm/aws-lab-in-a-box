# EKS Sample Application

## Overview

This directory contains a simple sample application that can be deployed to the Amazon EKS cluster created by the Lab-in-a-Box infrastructure. It provides a practical example for testing StrongDM's Kubernetes access capabilities and verifying that the EKS cluster is functioning correctly.

## Architecture

The sample application consists of:

- **NGINX Web Server**: A basic web server deployment with 3 replicas for high availability
- **Kubernetes Service**: Exposes the web server on port 80 within the cluster
- **Architecture Compatibility**: Configured to run on both ARM64 and AMD64 nodes

## Files

- `eks-sample-deployment.yaml`: Defines the NGINX deployment with 3 replicas
- `eks-sample-service.yaml`: Creates a service to expose the deployment internally

## Deployment Instructions

### Prerequisites

- An EKS cluster provisioned by the Lab-in-a-Box infrastructure (set `create_eks = true` in terraform.tfvars)
- kubectl configured to communicate with your EKS cluster
- Access to the EKS cluster through StrongDM

### Accessing the Cluster through StrongDM

1. Log in to StrongDM with appropriate permissions
2. Connect to the EKS cluster resource
3. StrongDM will provide a kubectl environment with the necessary permissions

### Deploying the Application

1. Apply the deployment manifest:

```bash
kubectl apply -f eks-sample-deployment.yaml
```

2. Apply the service manifest:

```bash
kubectl apply -f eks-sample-service.yaml
```

3. Verify the deployment:

```bash
kubectl get deployments
kubectl get pods
kubectl get services
```

### Verifying Access

After deployment, you should see:
- 3 running pods with the label `app=eks-sample-linux-app`
- A service named `eks-sample-linux-service`

## Accessing the Application

This sample application is configured with a ClusterIP service (the default), which makes it accessible only within the cluster. To access it externally, you would need to either:

1. Use kubectl port-forwarding:
```bash
kubectl port-forward service/eks-sample-linux-service 8080:80
```
Then access the application at http://localhost:8080

2. Or modify the service to use a LoadBalancer type (requires additional AWS configuration)

## Integration with StrongDM

This sample application demonstrates the following StrongDM capabilities:

- **Secure Kubernetes Access**: Access the cluster through StrongDM's authentication and authorization mechanisms
- **Just-in-Time Access**: Temporary credentials for kubectl operations
- **Audit Logging**: All kubectl commands are recorded and can be audited
- **RBAC Integration**: Access control based on StrongDM roles and permissions

## Customization

You can modify this sample application for your specific needs:

- Change the container image to test other applications
- Adjust resource limits or replicas to demonstrate scaling
- Add volume mounts to demonstrate persistent storage
- Implement Ingress resources for more complex networking scenarios

## Clean Up

To remove the sample application from your cluster:

```bash
kubectl delete -f eks-sample-service.yaml
kubectl delete -f eks-sample-deployment.yaml
```