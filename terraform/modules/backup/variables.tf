# ─────────────────────────────────────────────────────────────────────────────
# Module: backup — variables
# Purpose: Input variables for the Backup & DR module
# ─────────────────────────────────────────────────────────────────────────────

# ─── General ──────────────────────────────────────────────────────────────────

variable "aws_account_id" {
  description = "Management AWS Account ID"
  type        = string
}

variable "aws_region" {
  description = "Primary AWS region (eu-north-1)"
  type        = string
  default     = "eu-north-1"
}

variable "dr_region" {
  description = "Disaster Recovery region for cross-region backup copies"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Environment name (lab / prod)"
  type        = string
  default     = "lab"
}

variable "project_name" {
  description = "Project name prefix used in all resource names (e.g. 'forteca')"
  type        = string
  default     = "forteca"
}

# ─── Vault Lock ───────────────────────────────────────────────────────────────

variable "enable_vault_lock" {
  description = <<EOT
Enable Vault Lock (WORM) on the primary backup vault.
WARNING: Once changeable_for_days expires, the lock becomes permanent and
CANNOT be removed — not even by AWS Support or root user.
Set to true only when you are ready to demonstrate ISO 27001 A.12.3 compliance.
Default: false (safe for lab exploration)
EOT
  type        = bool
  default     = false
}

variable "vault_lock_min_retention_days" {
  description = <<EOT
Minimum number of days a backup must be retained in the locked vault.
AWS Backup will reject any backup job or lifecycle rule that would delete
a recovery point before this many days have passed.
EOT
  type        = number
  default     = 7
}

variable "vault_lock_max_retention_days" {
  description = <<EOT
Maximum number of days a backup can be retained in the locked vault.
Prevents accidentally keeping backups (and paying for storage) longer
than your data retention policy allows.
EOT
  type        = number
  default     = 365
}

variable "vault_lock_changeable_for_days" {
  description = <<EOT
Number of days during which the Vault Lock configuration can still be changed
or removed. After this window closes, the lock is PERMANENT (compliance mode).
AWS minimum: 3 days. Set to 3 for lab so you have time to undo if needed.
EOT
  type        = number
  default     = 3
}

# ─── Backup Retention ─────────────────────────────────────────────────────────

variable "daily_retention_days" {
  description = "How many days to keep daily backups"
  type        = number
  default     = 7 # 1 week — cost-efficient for lab
}

variable "weekly_retention_days" {
  description = "How many days to keep weekly backups (run every Sunday)"
  type        = number
  default     = 30 # 1 month
}

variable "dr_copy_retention_days" {
  description = "How many days to keep cross-region DR copies in eu-west-1"
  type        = number
  default     = 14 # 2 weeks — longer than daily, shorter than weekly for cost balance
}

# ─── Backup Window ────────────────────────────────────────────────────────────

variable "backup_window_start" {
  description = <<EOT
Cron expression (UTC) for when AWS Backup starts the backup job.
Format: cron(Minutes Hours DayOfMonth Month DayOfWeek Year)
Default: 02:00 UTC daily — low-traffic window for EU workloads.
EOT
  type        = string
  default     = "cron(0 2 * * ? *)"
}

variable "backup_window_complete_within_hours" {
  description = "Maximum hours the backup job is allowed to run before being marked failed"
  type        = number
  default     = 4 # If a backup takes longer than 4 hours, something is wrong
}

# ─── Tags ─────────────────────────────────────────────────────────────────────

variable "tags" {
  description = "Common resource tags applied to all backup resources"
  type        = map(string)
  default     = {}
}

# ─── Extracted from hardcoded values ──────────────────────────────────────────

variable "force_destroy" {
  description = "Allow Terraform to destroy backup vaults even if they contain recovery points. Set to false in production."
  type        = bool
  default     = true
}

variable "kms_deletion_window_days" {
  description = "Number of days KMS waits before permanently deleting a key scheduled for deletion (min 7, max 30)"
  type        = number
  default     = 7
}
