###############################################
# Organization
###############################################
resource "aws_organizations_organization" "this" {
  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "backup.amazonaws.com",
    "sso.amazonaws.com",
    "access-analyzer.amazonaws.com"
  ]

  # ALL required for SCPs — CONSOLIDATED_BILLING won't work
  feature_set = "ALL"

  # Explicitly enable SCP policy type
  enabled_policy_types = ["SERVICE_CONTROL_POLICY"]
}

###############################################
# Organizational Units
###############################################
resource "aws_organizations_organizational_unit" "this" {
  for_each  = var.org_units
  name      = each.key
  parent_id = aws_organizations_organization.this.roots[0].id
}

###############################################
# Member Accounts
###############################################
resource "aws_organizations_account" "this" {
  for_each = var.member_accounts
  name     = each.key
  email    = each.value.email

  parent_id = aws_organizations_organizational_unit.this[each.value.ou].id

  lifecycle {
    prevent_destroy = false # NOTE: set to true in production!
    ignore_changes  = [email, name]
  }

  tags = var.tags
}

###############################################
# SCPs — loaded from JSON files
###############################################
locals {
  scp_policies = {
    deny_region_restriction = file("${path.module}/policies/deny_region_restriction.json")
    deny_cloudtrail_delete  = file("${path.module}/policies/deny_cloudtrail_delete.json")
    deny_root_usage         = file("${path.module}/policies/deny_root_usage.json")
  }
}

resource "aws_organizations_policy" "this" {
  for_each    = local.scp_policies
  name        = each.key
  description = "${var.project_name} SCP: ${each.key}"
  type        = "SERVICE_CONTROL_POLICY"
  content     = each.value
  tags        = var.tags

}

# Attach every SCP to every OU
resource "aws_organizations_policy_attachment" "this" {
  for_each = {
    for combo in flatten([
      for ou_key, ou in aws_organizations_organizational_unit.this : [
        for scp_key in keys(aws_organizations_policy.this) : {
          key    = "${ou_key}-${scp_key}"
          ou_id  = ou.id
          scp_id = aws_organizations_policy.this[scp_key].id
        }
      ]
    ]) : combo.key => combo
  }

  policy_id = each.value.scp_id
  target_id = each.value.ou_id
}
