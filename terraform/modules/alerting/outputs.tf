# ─── Module 5: Alerting — Outputs ────────────────────────────────────────────
# Outputs bubble up values from this module to the calling environment (envs/management).
# Useful for: cross-module references, terraform output command, documentation.

output "ops_alerts_sns_arn" {
  description = "ARN of the operational alerts SNS topic (forteca-ops-alerts)"
  value       = aws_sns_topic.ops_alerts.arn
}

output "cloudwatch_dashboard_url" {
  description = "Direct URL to the Forteca Security & DR CloudWatch dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.forteca_security_dr.dashboard_name}"
}

output "alarm_arns" {
  description = "Map of alarm name => ARN for all CloudWatch alarms created by this module"
  value = {
    root_account_usage    = aws_cloudwatch_metric_alarm.root_account_usage.arn
    unauthorized_api_calls = aws_cloudwatch_metric_alarm.unauthorized_api_calls.arn
    console_login_no_mfa  = aws_cloudwatch_metric_alarm.console_login_no_mfa.arn
    cloudtrail_changes    = aws_cloudwatch_metric_alarm.cloudtrail_changes.arn
    backup_job_failed     = aws_cloudwatch_metric_alarm.backup_job_failed.arn
  }
}

output "eventbridge_rule_arns" {
  description = "Map of EventBridge rule name => ARN"
  value = {
    backup_job_failed      = aws_cloudwatch_event_rule.backup_job_failed.arn
    config_compliance_failed = aws_cloudwatch_event_rule.config_compliance_failed.arn
  }
}
