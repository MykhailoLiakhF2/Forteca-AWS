# ─── Organizations ────────────────────────────────────────────────────────

output "org_id" {
  description = "AWS Organization ID"
  value       = module.organizations.org_id
}

output "org_root_id" {
  description = "Root OU ID"
  value       = module.organizations.org_root_id
}

output "ou_ids" {
  description = "Map of OU name => OU ID"
  value       = module.organizations.ou_ids
}

output "member_account_ids" {
  description = "Map of account name => account ID"
  value       = module.organizations.member_account_ids
}

# ─── CloudTrail ───────────────────────────────────────────────────────────

output "cloudtrail_trail_arn" {
  description = "ARN of the CloudTrail organization trail"
  value       = module.cloudtrail.trail_arn
}

output "cloudtrail_s3_bucket" {
  description = "S3 bucket name for CloudTrail logs"
  value       = module.cloudtrail.s3_bucket_name
}

output "cloudtrail_kms_key_arn" {
  description = "KMS key ARN used for CloudTrail encryption"
  value       = module.cloudtrail.kms_key_arn
}

output "cloudtrail_log_group" {
  description = "CloudWatch Log Group name for CloudTrail"
  value       = module.cloudtrail.log_group_name
}

# ─── Security ─────────────────────────────────────────────────────────────

output "guardduty_detector_management_id" {
  description = "GuardDuty detector ID in management account"
  value       = module.security.guardduty_detector_management_id
}

output "guardduty_detector_security_id" {
  description = "GuardDuty detector ID in security account (delegated admin)"
  value       = module.security.guardduty_detector_security_id
}

output "guardduty_findings_bucket" {
  description = "S3 bucket name for GuardDuty findings export"
  value       = module.security.guardduty_findings_bucket_name
}

output "config_recorder_id" {
  description = "AWS Config recorder ID"
  value       = module.security.config_recorder_id
}

output "config_aggregator_arn" {
  description = "Config org aggregator ARN in security account"
  value       = module.security.config_aggregator_arn
}

output "config_delivery_bucket" {
  description = "S3 bucket name for Config delivery"
  value       = module.security.config_delivery_bucket_name
}

output "access_analyzer_arn" {
  description = "IAM Access Analyzer ARN (organization scope)"
  value       = module.security.access_analyzer_arn
}

output "sns_security_alerts_arn" {
  description = "SNS topic ARN for HIGH/CRITICAL security alerts"
  value       = module.security.sns_security_alerts_topic_arn
}

# ─── Backup & DR ──────────────────────────────────────────────────────────────────

output "backup_vault_primary_arn" {
  description = "ARN of the primary backup vault (eu-north-1)"
  value       = module.backup.backup_vault_primary_arn
}

output "backup_vault_dr_arn" {
  description = "ARN of the DR backup vault (eu-west-1)"
  value       = module.backup.backup_vault_dr_arn
}

output "backup_plan_arn" {
  description = "ARN of the Forteca backup plan"
  value       = module.backup.backup_plan_arn
}

output "backup_vault_lock_enabled" {
  description = "Whether Vault Lock (WORM) is currently active"
  value       = module.backup.vault_lock_enabled
}

# ─── Alerting ──────────────────────────────────────────────────────────────────

output "ops_alerts_sns_arn" {
  description = "ARN of the operational alerts SNS topic"
  value       = module.alerting.ops_alerts_sns_arn
}

output "cloudwatch_dashboard_url" {
  description = "URL to the Forteca Security & DR CloudWatch dashboard"
  value       = module.alerting.cloudwatch_dashboard_url
}

output "alarm_arns" {
  description = "Map of all CloudWatch alarm ARNs created by Module 5"
  value       = module.alerting.alarm_arns
}


output "backup_iam_role_arn" {
  description = "ARN of the IAM role used by AWS Backup service"
  value       = module.backup.backup_iam_role_arn
}
