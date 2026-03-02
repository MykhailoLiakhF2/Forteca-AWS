variable "aws_account_id" {
  description = "Management AWS Account ID"
  type        = string
}

variable "organization_id" {
  description = "AWS Organizations ID (o-xxxxxxxxxx)"
  type        = string
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

variable "region" {
  description = "Primary AWS region"
  type        = string
  default     = "eu-north-1"
}

# ─── Extracted from hardcoded values ──────────────────────────────────────────

variable "force_destroy" {
  description = "Allow Terraform to destroy S3 buckets even if they contain objects. Set to false in production."
  type        = bool
  default     = true
}

variable "kms_deletion_window_days" {
  description = "Number of days KMS waits before permanently deleting a key scheduled for deletion (min 7, max 30)"
  type        = number
  default     = 7
}

variable "cloudtrail_log_retention_days" {
  description = "Retention period (days) for CloudWatch Log Group where CloudTrail writes events"
  type        = number
  default     = 90
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
  description = "Days before permanently deleting S3 objects (default 2555 = 7 years, ISO 27001 audit log retention)"
  type        = number
  default     = 2555
}
