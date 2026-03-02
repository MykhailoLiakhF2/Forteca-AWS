variable "aws_region" {
  description = "Primary AWS region"
  type        = string
  default     = "eu-north-1"
}

variable "project_name" {
  description = "Project name prefix used in all resource names (e.g. 'forteca')"
  type        = string
  default     = "forteca"
}

variable "aws_account_id" {
  description = "Management AWS Account ID"
  type        = string
}

variable "security_account_id" {
  description = "Security AWS Account ID — delegated admin for GuardDuty, Security Hub, Config Aggregator"
  type        = string
}

variable "environment" {
  description = "Environment name (lab / prod)"
  type        = string
  default     = "lab"
}

variable "member_accounts" {
  description = "Member accounts to create inside the org"
  type = map(object({
    email = string
    ou    = string
  }))
}

variable "tags" {
  description = "Common resource tags"
  type        = map(string)
  default     = {}
}

variable "alert_email" {
  description = "Email address to receive HIGH/CRITICAL security alerts"
  type        = string
}

# ─── Module 4: Backup & DR ────────────────────────────────────────────────────

variable "dr_region" {
  description = "Disaster Recovery region for cross-region backup copies"
  type        = string
  default     = "eu-west-1"
}

variable "enable_vault_lock" {
  description = <<EOT
Enable Vault Lock (WORM) on the primary backup vault.
WARNING: After changeable_for_days (3 days) expires, the lock is PERMANENT.
Keep false for normal lab work. Set true only to demonstrate ISO 27001 A.12.3.
EOT
  type        = bool
  default     = false
}

variable "daily_retention_days" {
  description = "How many days to keep daily backups (default 7)"
  type        = number
  default     = 7
}

variable "weekly_retention_days" {
  description = "How many days to keep weekly backups (default 30)"
  type        = number
  default     = 30
}

# ─── Module 5: Alerting ──────────────────────────────────────────────────────

variable "ops_alert_email" {
  description = <<EOT
Email address for operational alerts from the management account:
- Backup job failures
- AWS Config NON_COMPLIANT evaluations
- CloudTrail: root usage, unauthorized API calls, console login without MFA
EOT
  type        = string
}


variable "dr_copy_retention_days" {
  description = "How many days to keep cross-region DR copies (default 14)"
  type        = number
  default     = 14
}

# ─── Shared variables for all modules ─────────────────────────────────────────

variable "force_destroy" {
  description = "Allow Terraform to destroy S3 buckets and backup vaults with contents. Set to false in production."
  type        = bool
  default     = true
}

variable "kms_deletion_window_days" {
  description = "Number of days KMS waits before permanently deleting a key (min 7, max 30)"
  type        = number
  default     = 7
}

variable "s3_transition_ia_days" {
  description = "Days before transitioning S3 objects to STANDARD_IA storage class"
  type        = number
  default     = 90
}

variable "s3_transition_glacier_days" {
  description = "Days before transitioning S3 objects to GLACIER storage class"
  type        = number
  default     = 365
}

variable "s3_expiration_days" {
  description = "Days before permanently deleting S3 objects (default 2555 = 7 years, ISO 27001)"
  type        = number
  default     = 2555
}

variable "cloudtrail_log_retention_days" {
  description = "Retention period (days) for CloudWatch Log Group where CloudTrail writes events"
  type        = number
  default     = 90
}
