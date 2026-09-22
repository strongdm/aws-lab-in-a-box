#--------------------------------------------------------------
# Demo Access Configuration
#
# This file creates example StrongDM access management resources
# for demonstrating role-based access control, policies, and
# approval workflows. All resources are gated behind the
# create_demo_access feature flag.
#
# Components:
# - Roles with tag-based access rules
# - Cedar policies for fine-grained access control
# - Approval workflow for sensitive resource access
# - Workflow-role bindings
#
# Every rule and policy here is scoped to the Name tags this lab
# applies, so enabling the flag in a shared StrongDM organization
# cannot grant or deny access to resources outside this lab.
#--------------------------------------------------------------

locals {
  # Every lab resource carries the operator's tagset. The demo matches on the
  # environment tag, so it needs a value even when the tagset omits the key.
  demo_environment = lookup(var.tagset, "environment", "Lab")

  # StrongDM Name tags applied by the target modules. Access rules match tags
  # exactly, so the names are listed rather than pattern matched. Names of
  # targets that were not deployed simply match nothing.
  demo_database_targets = [
    "sdm-${var.name}-postgresql",
    "sdm-${var.name}-documentdb",
  ]

  # Databases plus the Windows target: the resources the demo routes through the
  # approval workflow.
  demo_sensitive_targets = concat(local.demo_database_targets, ["sdm-${var.name}-windows-target"])

  demo_cloud_targets = [
    "sdm-${var.name}-aws-cli-ro",
    "sdm-${var.name}-aws-console-ro",
    "sdm-${var.name}-s3-cli-ro",
    "sdm-${var.name}-s3-console-ro",
    "sdm-${var.name}-s3-cli-full",
    "sdm-${var.name}-s3-console-full",
    "sdm-${var.name}-glue-cli-full",
    "sdm-${var.name}-glue-console-full",
  ]
}

#--------------------------------------------------------------
# Roles
#
# Roles use tag-based access rules to dynamically grant access
# to resources based on their tags. This means new resources
# matching the tags are automatically included.
#--------------------------------------------------------------

# DBA Team - Access to all database resources (PostgreSQL, DocumentDB)
resource "sdm_role" "dba_team" {
  count = var.create_demo_access == false ? 0 : 1
  name  = "${var.name}-DBA-Team"

  access_rules = jsonencode([
    for target in local.demo_database_targets : {
      tags = {
        class = "target"
        Name  = target
      }
    }
  ])
}

# DevOps Team - Access to Linux servers and Kubernetes clusters
resource "sdm_role" "devops_team" {
  count = var.create_demo_access == false ? 0 : 1
  name  = "${var.name}-DevOps-Team"

  access_rules = jsonencode([
    {
      tags = {
        class = "target"
        Name  = "sdm-${var.name}-target-ssh"
      }
    },
    {
      tags = {
        class = "target"
        Name  = "sdm-${var.name}-eks"
      }
    }
  ])
}

# Windows Admin - Access to Windows/RDP targets and domain controller
resource "sdm_role" "windows_admin" {
  count = var.create_demo_access == false ? 0 : 1
  name  = "${var.name}-Windows-Admin"

  access_rules = jsonencode([
    {
      tags = {
        class = "target"
        Name  = "sdm-${var.name}-windows-target"
      }
    },
    {
      tags = {
        class = "sdminfra"
        Name  = "sdm-${var.name}-domain-controller"
      }
    }
  ])
}

# Cloud Access - Access to the AWS CLI and console profiles (ReadOnly, S3, Glue)
resource "sdm_role" "cloud_access" {
  count = var.create_demo_access == false ? 0 : 1
  name  = "${var.name}-Cloud-Access"

  access_rules = jsonencode([
    for target in local.demo_cloud_targets : {
      tags = {
        class = "target"
        Name  = target
      }
    }
  ])
}

# Full Access - Access to all targets in this environment (for demo/admin)
resource "sdm_role" "full_access" {
  count = var.create_demo_access == false ? 0 : 1
  name  = "${var.name}-Full-Access"

  access_rules = jsonencode([
    {
      tags = {
        environment = local.demo_environment
      }
    }
  ])
}

#--------------------------------------------------------------
# Policies (Cedar)
#
# Cedar policies are an additional authorization gate evaluated
# alongside the access grants above; they never create a grant.
# They also apply organization wide, so both policies below are
# scoped to this lab's Name tags.
#
# Policy enforcement must be enabled for the organization (and
# the Policy Editor SKU present) for either policy to take
# effect at runtime.
#--------------------------------------------------------------

# Require a justification before the DBA team connects to a database target.
# Justification is a requirement annotation on a permit, so this statement is
# itself an authorizing permit - it deliberately repeats the DBA role and
# database targets rather than matching more broadly.
resource "sdm_policy" "require_db_justification" {
  count       = var.create_demo_access == false ? 0 : 1
  name        = "${var.name}-require-db-justification"
  description = "Require the ${var.name}-DBA-Team role to provide a justification when connecting to this lab's database targets"

  policy = <<-CEDAR
    @justify("?prompt=Why%20do%20you%20need%20access%20to%20this%20database%3F&cache=15m")
    permit (
      principal in StrongDM::Role::"${one(sdm_role.dba_team[*].id)}",
      action == StrongDM::Action::"connect",
      resource
    )
    when {
      resource has sdm &&
      resource.sdm.hasTag("Name") &&
      (resource.sdm.getTag("Name") == "sdm-${var.name}-postgresql" ||
       resource.sdm.getTag("Name") == "sdm-${var.name}-documentdb")
    };
  CEDAR
}

# Deny connections to this lab outside 08:00-18:00 UTC, Monday to Friday.
# minuteOfDay is UTC minutes since midnight (480 = 08:00, 1080 = 18:00) and
# dayOfWeek runs Sunday = 1 through Saturday = 7. A resource without the Name
# or environment tag is left unaffected rather than denied.
resource "sdm_policy" "business_hours_only" {
  count       = var.create_demo_access == false ? 0 : 1
  name        = "${var.name}-business-hours-only"
  description = "Demonstrate time-based access control by denying connections to this lab's resources outside 08:00-18:00 UTC on weekdays"

  policy = <<-CEDAR
    @error("Access to this lab is limited to 08:00-18:00 UTC, Monday to Friday")
    forbid (
      principal,
      action == StrongDM::Action::"connect",
      resource
    )
    when {
      resource has sdm &&
      resource.sdm.hasTag("Name") &&
      resource.sdm.getTag("Name") like "sdm-${var.name}-*" &&
      resource.sdm.hasTag("environment") &&
      resource.sdm.getTag("environment") == "${local.demo_environment}" &&
      context has utcNow &&
      (context.utcNow.dayOfWeek < 2 ||
       context.utcNow.dayOfWeek > 6 ||
       context.utcNow.minuteOfDay < 480 ||
       context.utcNow.minuteOfDay >= 1080)
    };
  CEDAR
}

#--------------------------------------------------------------
# Approval Workflows
#
# Workflows control how users request and receive access to
# resources. The standard workflow grants automatically; the
# sensitive workflow requires a member of the approver group to
# approve the request.
#--------------------------------------------------------------

# Approver group - holds the accounts allowed to approve sensitive requests.
# The group is created empty; populate it with demo_approver_account_ids or in
# the StrongDM UI, otherwise requests routed to it can never be approved.
resource "sdm_group" "approvers" {
  count       = var.create_demo_access == false ? 0 : 1
  name        = "${var.name}-Approvers"
  description = "Approves access requests for the sensitive resources in the ${var.name} lab"
}

resource "sdm_account_group" "approvers" {
  for_each = var.create_demo_access == false ? toset([]) : toset(var.demo_approver_account_ids)

  group_id   = one(sdm_group.approvers[*].id)
  account_id = each.value
}

# Automatic approval flow for standard resources. The workflow's own auto_grant
# argument is deprecated, so the grant is expressed as an approval flow instead.
resource "sdm_approval_workflow" "auto_approve" {
  count         = var.create_demo_access == false ? 0 : 1
  name          = "${var.name}-Auto-Approve"
  approval_mode = "automatic"
  description   = "Automatically approves access requests for standard resources"
}

# Manual approval flow for sensitive resources requiring sign-off
resource "sdm_approval_workflow" "manager_approval" {
  count         = var.create_demo_access == false ? 0 : 1
  name          = "${var.name}-Manager-Approval"
  approval_mode = "manual"
  description   = "Requires manual approval for sensitive resource access"

  approval_step {
    approvers {
      group_id = one(sdm_group.approvers[*].id)
    }
  }
}

# Auto-grant workflow for standard resources (Linux, Kubernetes, cloud profiles)
resource "sdm_workflow" "auto_grant_standard" {
  count            = var.create_demo_access == false ? 0 : 1
  name             = "${var.name}-Auto-Grant-Standard"
  enabled          = true
  approval_flow_id = one(sdm_approval_workflow.auto_approve[*].id)
  description      = "Automatically grants access to standard resources for approved roles"

  access_rules = jsonencode([
    {
      tags = {
        class       = "target"
        environment = local.demo_environment
      }
    }
  ])

  access_request_fixed_duration = "1h"
}

# Approval-required workflow for sensitive resources (databases, Windows)
resource "sdm_workflow" "approval_required_sensitive" {
  count            = var.create_demo_access == false ? 0 : 1
  name             = "${var.name}-Approval-Required-Sensitive"
  enabled          = true
  approval_flow_id = one(sdm_approval_workflow.manager_approval[*].id)
  description      = "Requires approval for access to sensitive database and Windows resources"

  access_rules = jsonencode([
    for target in local.demo_sensitive_targets : {
      tags = {
        class = "target"
        Name  = target
      }
    }
  ])

  access_request_max_duration = "8h"
}

#--------------------------------------------------------------
# Workflow-Role Bindings
#
# These bind roles to workflows, defining which roles can
# use which workflows to request access.
#--------------------------------------------------------------

# DBA Team can use the sensitive approval workflow
resource "sdm_workflow_role" "dba_sensitive" {
  count       = var.create_demo_access == false ? 0 : 1
  workflow_id = one(sdm_workflow.approval_required_sensitive[*].id)
  role_id     = one(sdm_role.dba_team[*].id)
}

# Windows Admin covers the Windows target, so it uses the sensitive workflow
resource "sdm_workflow_role" "windows_admin_sensitive" {
  count       = var.create_demo_access == false ? 0 : 1
  workflow_id = one(sdm_workflow.approval_required_sensitive[*].id)
  role_id     = one(sdm_role.windows_admin[*].id)
}

# DevOps Team can use the auto-grant workflow
resource "sdm_workflow_role" "devops_standard" {
  count       = var.create_demo_access == false ? 0 : 1
  workflow_id = one(sdm_workflow.auto_grant_standard[*].id)
  role_id     = one(sdm_role.devops_team[*].id)
}

# Cloud Access only covers standard cloud profiles, so it auto-grants
resource "sdm_workflow_role" "cloud_access_standard" {
  count       = var.create_demo_access == false ? 0 : 1
  workflow_id = one(sdm_workflow.auto_grant_standard[*].id)
  role_id     = one(sdm_role.cloud_access[*].id)
}

# Full Access can use both workflows
resource "sdm_workflow_role" "full_access_standard" {
  count       = var.create_demo_access == false ? 0 : 1
  workflow_id = one(sdm_workflow.auto_grant_standard[*].id)
  role_id     = one(sdm_role.full_access[*].id)
}

resource "sdm_workflow_role" "full_access_sensitive" {
  count       = var.create_demo_access == false ? 0 : 1
  workflow_id = one(sdm_workflow.approval_required_sensitive[*].id)
  role_id     = one(sdm_role.full_access[*].id)
}
