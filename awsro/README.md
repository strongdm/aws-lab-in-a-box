# AWS Read-Only Role Module for StrongDM Lab

## Overview

This module creates an IAM role that provides read-only access to AWS resources through StrongDM. It enables secure, delegated access to AWS resources without providing direct credentials, demonstrating StrongDM's capability to manage cloud service access.

## Architecture

The module provisions:
- An IAM role with trust relationships to EC2 service and the StrongDM gateway role
- AWS managed ReadOnlyAccess policy attachment
- Proper tagging for resource management

## Use Cases for Partner Training

1. **Cloud Access Control**: Demonstrate how StrongDM can manage access to cloud resources like AWS
2. **Temporary Console Access**: Show how StrongDM enables time-limited AWS Console access
3. **Infrastructure Visibility**: Provide safe, read-only access to AWS infrastructure for auditing purposes
4. **CLI Access Management**: Control programmatic access to AWS through StrongDM's access workflows

## Configuration

### Basic Usage

```hcl
module "awsro" {
  source = "../awsro"
  tagset = var.tagset
  role   = aws_iam_role.gateway.arn
}
```

### Required Variables

- `tagset`: Tags to apply to resources
- `role`: ARN of the role that should be allowed to assume the read-only role

## Integration with StrongDM

The main module's `awsrotarget.tf` file demonstrates how to create StrongDM resources that use this role:

1. **AWS CLI Access**: Provides programmatic access to AWS through StrongDM
2. **AWS Console Access**: Creates a StrongDM resource for web console access

## Best Practices

For production environments (unlike this demo):
- Create more granular IAM roles with specific permissions instead of using ReadOnlyAccess
- Use temporary session credentials with short lifetimes
- Implement conditional access based on source IP, time of day, etc.
- Enable CloudTrail logging for all role assumption activities