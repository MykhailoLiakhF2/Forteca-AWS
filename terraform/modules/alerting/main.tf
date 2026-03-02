# ─── Module 5: Alerting ─────────────────────────────────────────────────────
#
# This module implements the "detection → notification → visibility" layer:
#
#  1. SNS topic  — "${var.project_name}-ops-alerts" receives all operational alarms
#  2. CloudWatch Metric Filters — parse CloudTrail logs, count security events
#  3. CloudWatch Alarms — fire when event counts exceed threshold
#  4. EventBridge rules — catch AWS Backup job failures in real time
#  5. CloudWatch Dashboard — single pane of glass for DR + Security metrics
#
# ISO 27001 controls covered:
#   A.12.4.1 — Event logging monitored
#   A.12.4.3 — Administrator and operator logs reviewed
#   A.16.1.2 — Reporting information security events
# ─────────────────────────────────────────────────────────────────────────────


# ─── 1. SNS TOPIC: Operational Alerts ────────────────────────────────────────

resource "aws_sns_topic" "ops_alerts" {
  name = "${var.project_name}-ops-alerts"

  # KMS encryption at rest — even notification payloads are encrypted.
  # We use the AWS-managed key for SNS (no extra cost, no management overhead).
  kms_master_key_id = "alias/aws/sns"

  tags = merge(var.tags, {
    Name    = "${var.project_name}-ops-alerts"
    Module  = "alerting"
    Purpose = "Operational alerts backup failures compliance CloudTrail"
  })
}

# Email subscription
resource "aws_sns_topic_subscription" "ops_alerts_email" {
  topic_arn = aws_sns_topic.ops_alerts.arn
  protocol  = "email"
  endpoint  = var.ops_alert_email
}

# SNS topic policy
resource "aws_sns_topic_policy" "ops_alerts" {
  arn = aws_sns_topic.ops_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudWatchAlarms"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.ops_alerts.arn
        # Condition: only alarms in THIS account can publish.
        # Prevents cross-account abuse.
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:aws:cloudwatch:${var.aws_region}:${var.aws_account_id}:alarm:*"
          }
        }
      },
      {
        Sid    = "AllowEventBridge"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.ops_alerts.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:aws:events:${var.aws_region}:${var.aws_account_id}:rule/*"
          }
        }
      }
    ]
  })
}


# ─── 2. CLOUDWATCH METRIC FILTERS ────────────────────────────────────────────


# 2a. Root Account Usage
# ISO 27001 A.9.2.3 — privileged account usage must be monitored.
resource "aws_cloudwatch_log_metric_filter" "root_account_usage" {
  name           = "${var.project_name}-root-account-usage"
  log_group_name = var.cloudtrail_log_group_name

  # Match events where: userIdentity type is "Root" AND it's an API call (not MFA setup etc.)
  pattern = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootAccountUsageCount"
    namespace = "${title(var.project_name)}/SecurityEvents"  # Custom namespace — our own metrics "folder"
    value     = "1"                       # Each matching log line adds 1 to the counter
    unit      = "Count"
  }
}

# 2b. Unauthorized API Calls
# ISO 27001 A.12.4.1 — unauthorized access attempts must be logged and reviewed.
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  name           = "${var.project_name}-unauthorized-api-calls"
  log_group_name = var.cloudtrail_log_group_name

  # errorCode field contains "AccessDenied" or "UnauthorizedOperation"
  pattern = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name      = "UnauthorizedAPICallsCount"
    namespace = "${title(var.project_name)}/SecurityEvents"
    value     = "1"
    unit      = "Count"
  }
}

# 2c. Console Login Without MFA
# ISO 27001 A.9.4.2 — secure log-on procedures must enforce MFA.
resource "aws_cloudwatch_log_metric_filter" "console_login_no_mfa" {
  name           = "${var.project_name}-console-login-no-mfa"
  log_group_name = var.cloudtrail_log_group_name

  # Match ConsoleLogin events where MFA was NOT used
  pattern = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"

  metric_transformation {
    name      = "ConsoleLoginWithoutMFACount"
    namespace = "${title(var.project_name)}/SecurityEvents"
    value     = "1"
    unit      = "Count"
  }
}

# 2d. CloudTrail Disabled or Modified
# ISO 27001 A.12.4.2 — protection of log information.
resource "aws_cloudwatch_log_metric_filter" "cloudtrail_changes" {
  name           = "${var.project_name}-cloudtrail-changes"
  log_group_name = var.cloudtrail_log_group_name

  # Match any of the "dangerous" CloudTrail management API calls
  pattern = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"

  metric_transformation {
    name      = "CloudTrailChangesCount"
    namespace = "${title(var.project_name)}/SecurityEvents"
    value     = "1"
    unit      = "Count"
  }
}


# ─── 3. CLOUDWATCH ALARMS ─────────────────────────────────────────────────────


# 3a. Root Account Usage Alarm
resource "aws_cloudwatch_metric_alarm" "root_account_usage" {
  alarm_name          = "${var.project_name}-root-account-usage"
  alarm_description   = "CRITICAL: Root account API call detected. ISO 27001 A.9.2.3 violation."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1       # Alert on first breach — root usage is always urgent
  metric_name         = "RootAccountUsageCount"
  namespace           = "${title(var.project_name)}/SecurityEvents"
  period              = 300     # 5-minute window
  statistic           = "Sum"   # Sum all events in the window
  threshold           = 1       # Alert as soon as count >= 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.ops_alerts.arn]
  ok_actions    = [aws_sns_topic.ops_alerts.arn]  # Also notify when alarm clears

  tags = merge(var.tags, { Module = "alerting" })
}

# 3b. Unauthorized API Calls Alarm
resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  alarm_name          = "${var.project_name}-unauthorized-api-calls"
  alarm_description   = "WARNING: Multiple unauthorized API calls detected. Possible misconfiguration or intrusion attempt."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICallsCount"
  namespace           = "${title(var.project_name)}/SecurityEvents"
  period              = 300
  statistic           = "Sum"
  threshold           = 5       # Allow a small buffer — 5+ in 5 min is suspicious
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.ops_alerts.arn]

  tags = merge(var.tags, { Module = "alerting" })
}

# 3c. Console Login Without MFA Alarm
resource "aws_cloudwatch_metric_alarm" "console_login_no_mfa" {
  alarm_name          = "${var.project_name}-console-login-no-mfa"
  alarm_description   = "CRITICAL: Console login without MFA. ISO 27001 A.9.4.2 violation."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ConsoleLoginWithoutMFACount"
  namespace           = "${title(var.project_name)}/SecurityEvents"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.ops_alerts.arn]

  tags = merge(var.tags, { Module = "alerting" })
}

# 3d. CloudTrail Changes Alarm
resource "aws_cloudwatch_metric_alarm" "cloudtrail_changes" {
  alarm_name          = "${var.project_name}-cloudtrail-changes"
  alarm_description   = "CRITICAL: CloudTrail was modified or stopped. ISO 27001 A.12.4.2 violation."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CloudTrailChangesCount"
  namespace           = "${title(var.project_name)}/SecurityEvents"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.ops_alerts.arn]

  tags = merge(var.tags, { Module = "alerting" })
}

# 3e. Backup Job Failures Alarm
# AWS Backup publishes metrics to the AWS/Backup namespace automatically.
# NumberOfBackupJobsFailed counts jobs that ended in FAILED or ABORTED state.
resource "aws_cloudwatch_metric_alarm" "backup_job_failed" {
  alarm_name          = "${var.project_name}-backup-job-failed"
  alarm_description   = "WARNING: One or more AWS Backup jobs failed. DR objective may be at risk. ISO 27001 A.12.3.1."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "NumberOfBackupJobsFailed"
  namespace           = "AWS/Backup"   # Built-in AWS namespace — no filter needed
  period              = 3600           # 1-hour window for backup metrics
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.ops_alerts.arn]

  tags = merge(var.tags, { Module = "alerting" })
}


# ─── 4. EVENTBRIDGE RULES ─────────────────────────────────────────────────────


# 4a. Backup Job Failure → SNS
resource "aws_cloudwatch_event_rule" "backup_job_failed" {
  name        = "${var.project_name}-backup-job-failed"
  description = "Catch AWS Backup job failures and aborts in real time. ISO 27001 A.12.3.1."

  event_pattern = jsonencode({
    source      = ["aws.backup"]
    detail-type = ["Backup Job State Change"]
    detail = {
      # Match only terminal failure states
      state = ["FAILED", "ABORTED", "EXPIRED"]
    }
  })

  tags = merge(var.tags, { Module = "alerting" })
}

resource "aws_cloudwatch_event_target" "backup_job_failed_sns" {
  rule      = aws_cloudwatch_event_rule.backup_job_failed.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.ops_alerts.arn

  # Transform the raw event JSON into a human-readable email body.
  # InputTransformer extracts specific fields and formats them as a message.
  input_transformer {
    input_paths = {
      jobId       = "$.detail.backupJobId"
      state       = "$.detail.state"
      vaultName   = "$.detail.backupVaultName"
      resourceArn = "$.detail.resourceArn"
      startTime   = "$.detail.creationDate"
    }
    # Placeholders in angle brackets are replaced with extracted values.
    input_template = "\"AWS Backup job FAILED\\nJob ID: <jobId>\\nState: <state>\\nVault: <vaultName>\\nResource: <resourceArn>\\nStarted: <startTime>\\n\\nCheck the AWS Backup console for details.\""
  }
}


# 4b. Config Compliance Change → SNS
# AWS Config evaluates rules continuously. When a resource becomes NON_COMPLIANT,
# it publishes a "Config Rules Compliance Change" event to EventBridge.
# This gives us immediate notification of compliance violations.
resource "aws_cloudwatch_event_rule" "config_compliance_failed" {
  name        = "${var.project_name}-config-compliance-failed"
  description = "Alert on AWS Config rule NON_COMPLIANT evaluation. ISO 27001 A.18.2.2."

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })

  tags = merge(var.tags, { Module = "alerting" })
}

resource "aws_cloudwatch_event_target" "config_compliance_failed_sns" {
  rule      = aws_cloudwatch_event_rule.config_compliance_failed.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.ops_alerts.arn

  input_transformer {
    input_paths = {
      configRuleName = "$.detail.configRuleName"
      resourceType   = "$.detail.resourceType"
      resourceId     = "$.detail.resourceId"
      complianceType = "$.detail.newEvaluationResult.complianceType"
    }
    input_template = "\"AWS Config COMPLIANCE VIOLATION\\nRule: <configRuleName>\\nResource Type: <resourceType>\\nResource ID: <resourceId>\\nStatus: <complianceType>\\n\\nReview in AWS Config console.\""
  }
}


# ─── 5. CLOUDWATCH DASHBOARD ──────────────────────────────────────────────────

resource "aws_cloudwatch_dashboard" "forteca_security_dr" {
  dashboard_name = "${title(var.project_name)}-Security-DR"

  # templatefile() would be cleaner but jsonencode() keeps everything in one file.
  # We use a local variable to build the JSON to avoid escaping issues.
  dashboard_body = jsonencode({
    widgets = [

      # ── Row 0: Title text widget ──────────────────────────────────────────
      {
        type   = "text"
        x = 0
        y = 0
        width  = 24
        height = 2
        properties = {
          markdown = "# Forteca-AWS — Security & DR Dashboard\n**Account:** ${var.aws_account_id} | **Region:** ${var.aws_region} | **DR Region:** ${var.dr_region} | **Environment:** ${var.environment}"
        }
      },

      # ── Row 1: Security Events ─────────────────────────────────────────────
      {
        type   = "metric"
        x = 0
        y = 2
        width  = 6
        height = 6
        properties = {
          title  = "Root Account Usage (5-min)"
          view   = "timeSeries"
          region = var.aws_region
          metrics = [
            ["${title(var.project_name)}/SecurityEvents", "RootAccountUsageCount", { stat = "Sum", period = 300, color = "#d62728" }]
          ]
          yAxis = { left = { min = 0 } }
          annotations = {
            horizontal = [{ value = 1, label = "ALARM threshold", color = "#d62728" }]
          }
        }
      },

      {
        type   = "metric"
        x = 6
        y = 2
        width  = 6
        height = 6
        properties = {
          title  = "Unauthorized API Calls (5-min)"
          view   = "timeSeries"
          region = var.aws_region
          metrics = [
            ["${title(var.project_name)}/SecurityEvents", "UnauthorizedAPICallsCount", { stat = "Sum", period = 300, color = "#ff7f0e" }]
          ]
          yAxis = { left = { min = 0 } }
          annotations = {
            horizontal = [{ value = 5, label = "ALARM threshold", color = "#ff7f0e" }]
          }
        }
      },

      {
        type   = "metric"
        x = 12
        y = 2
        width  = 6
        height = 6
        properties = {
          title  = "Console Logins Without MFA (5-min)"
          view   = "timeSeries"
          region = var.aws_region
          metrics = [
            ["${title(var.project_name)}/SecurityEvents", "ConsoleLoginWithoutMFACount", { stat = "Sum", period = 300, color = "#d62728" }]
          ]
          yAxis = { left = { min = 0 } }
        }
      },

      {
        type   = "metric"
        x = 18
        y = 2
        width  = 6
        height = 6
        properties = {
          title  = "CloudTrail Modifications (5-min)"
          view   = "timeSeries"
          region = var.aws_region
          metrics = [
            ["${title(var.project_name)}/SecurityEvents", "CloudTrailChangesCount", { stat = "Sum", period = 300, color = "#9467bd" }]
          ]
          yAxis = { left = { min = 0 } }
        }
      },

      # ── Row 2: Backup Health ───────────────────────────────────────────────
      {
        type   = "metric"
        x = 0
        y = 8
        width  = 8
        height = 6
        properties = {
          title  = "Backup Jobs Completed (1-hour)"
          view   = "timeSeries"
          region = var.aws_region
          metrics = [
            ["AWS/Backup", "NumberOfBackupJobsCompleted", { stat = "Sum", period = 3600, color = "#2ca02c" }]
          ]
          yAxis = { left = { min = 0 } }
        }
      },

      {
        type   = "metric"
        x = 8
        y = 8
        width  = 8
        height = 6
        properties = {
          title  = "Backup Jobs Failed (1-hour) ⚠"
          view   = "timeSeries"
          region = var.aws_region
          metrics = [
            ["AWS/Backup", "NumberOfBackupJobsFailed", { stat = "Sum", period = 3600, color = "#d62728" }]
          ]
          yAxis = { left = { min = 0 } }
          annotations = {
            horizontal = [{ value = 1, label = "ALARM threshold", color = "#d62728" }]
          }
        }
      },

      {
        type   = "metric"
        x = 16
        y = 8
        width  = 8
        height = 6
        properties = {
          title  = "Restore Jobs Completed (1-hour)"
          view   = "timeSeries"
          region = var.aws_region
          metrics = [
            ["AWS/Backup", "NumberOfRestoreJobsCompleted", { stat = "Sum", period = 3600, color = "#1f77b4" }]
          ]
          yAxis = { left = { min = 0 } }
        }
      },

      # ── Row 3: Alarm Status ────────────────────────────────────────────────
      # AlarmWidget shows current state (OK / ALARM / INSUFFICIENT_DATA) as colored circles.
      {
        type   = "alarm"
        x = 0
        y = 14
        width  = 24
        height = 4
        properties = {
          title  = "Active Alarms — Forteca Security & DR"
          alarms = [
            "arn:aws:cloudwatch:${var.aws_region}:${var.aws_account_id}:alarm:${var.project_name}-root-account-usage",
            "arn:aws:cloudwatch:${var.aws_region}:${var.aws_account_id}:alarm:${var.project_name}-unauthorized-api-calls",
            "arn:aws:cloudwatch:${var.aws_region}:${var.aws_account_id}:alarm:${var.project_name}-console-login-no-mfa",
            "arn:aws:cloudwatch:${var.aws_region}:${var.aws_account_id}:alarm:${var.project_name}-cloudtrail-changes",
            "arn:aws:cloudwatch:${var.aws_region}:${var.aws_account_id}:alarm:${var.project_name}-backup-job-failed"
          ]
        }
      }

    ]
  })
}
