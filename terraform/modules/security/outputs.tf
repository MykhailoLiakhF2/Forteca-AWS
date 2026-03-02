# ─── GuardDuty ────────────────────────────────────────────────────────────

output "guardduty_detector_management_id" {
  description = "GuardDuty detector ID in management account"
  value       = aws_guardduty_detector.management.id
}

output "guardduty_detector_security_id" {
  description = "GuardDuty detector ID in security account (delegated admin)"
  value       = data.aws_guardduty_detector.security.id
}

output "guardduty_findings_bucket_name" {
  description = "S3 bucket name for GuardDuty findings export"
  value       = aws_s3_bucket.guardduty_findings.id
}

output "guardduty_findings_bucket_arn" {
  description = "S3 bucket ARN for GuardDuty findings export"
  value       = aws_s3_bucket.guardduty_findings.arn
}

output "guardduty_kms_key_arn" {
  description = "KMS key ARN used for GuardDuty findings encryption"
  value       = aws_kms_key.guardduty.arn
}

# ─── Security Hub ─────────────────────────────────────────────────────────

output "securityhub_standards_fsbp_arn" {
  description = "ARN of the AWS FSBP Security Hub standards subscription"
  value       = aws_securityhub_standards_subscription.fsbp.id
}

output "securityhub_standards_cis_arn" {
  description = "ARN of the CIS AWS Foundations Benchmark subscription"
  value       = aws_securityhub_standards_subscription.cis.id
}

output "securityhub_standards_pci_arn" {
  description = "ARN of the PCI DSS standards subscription"
  value       = aws_securityhub_standards_subscription.pci.id
}

# ─── Config ───────────────────────────────────────────────────────────────

output "config_recorder_id" {
  description = "AWS Config recorder ID"
  value       = aws_config_configuration_recorder.main.id
}

output "config_delivery_bucket_name" {
  description = "S3 bucket name for Config delivery snapshots"
  value       = aws_s3_bucket.config.id
}

output "config_delivery_bucket_arn" {
  description = "S3 bucket ARN for Config delivery snapshots"
  value       = aws_s3_bucket.config.arn
}

output "config_aggregator_arn" {
  description = "ARN of the Config organization aggregator in security account"
  value       = aws_config_configuration_aggregator.org.arn
}

output "config_kms_key_arn" {
  description = "KMS key ARN used for Config S3 encryption"
  value       = aws_kms_key.config.arn
}

# ─── IAM Access Analyzer ──────────────────────────────────────────────────

output "access_analyzer_arn" {
  description = "ARN of the IAM Access Analyzer (organization scope)"
  value       = aws_accessanalyzer_analyzer.org.arn
}

# ─── Alerting ─────────────────────────────────────────────────────────────

output "sns_security_alerts_topic_arn" {
  description = "SNS topic ARN for HIGH/CRITICAL security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "sns_kms_key_arn" {
  description = "KMS key ARN used for SNS alerts topic encryption"
  value       = aws_kms_key.sns.arn
}
