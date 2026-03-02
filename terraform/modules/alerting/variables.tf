# ─── Module 5: Alerting ─────────────────────────────────────────────────────
# Input variables for the alerting module.
# All values are passed from envs/management/main.tf.

variable "aws_account_id" {
  description = "Management AWS Account ID"
  type        = string
}

variable "aws_region" {
  description = "Primary AWS region"
  type        = string
}

variable "environment" {
  description = "Environment name (lab / prod)"
  type        = string
}

variable "project_name" {
  description = "Project name prefix used in all resource names (e.g. 'forteca')"
  type        = string
  default     = "forteca"
}

variable "ops_alert_email" {
  description = <<EOT
Email address for OPERATIONAL alerts:
- Backup job failures
- Config compliance violations
- CloudTrail: root usage, unauthorized API calls, console login without MFA
Different from security_alert_email (Module 3) — that one is in the security account.
Here we send ops-level notifications from the management account.
EOT
  type        = string
}

variable "cloudtrail_log_group_name" {
  description = <<EOT
Name of the CloudWatch Log Group where CloudTrail writes its events.
Created in Module 2: /aws/cloudtrail/${var.project_name}-org-trail
We create Metric Filters on this log group to count specific API patterns.
EOT
  type        = string
  # default     = "/aws/cloudtrail/${var.project_name}-org-trail" # Note: Terraform variables cannot interpolate in default
}

variable "dr_region" {
  description = "DR region — used as label in dashboard only"
  type        = string
  default     = "eu-west-1"
}

variable "tags" {
  description = "Common resource tags applied to all resources"
  type        = map(string)
  default     = {}
}
