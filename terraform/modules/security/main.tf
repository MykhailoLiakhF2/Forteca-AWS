# ═══════════════════════════════════════════════════════════════════════════
# Module: security
#
# Architecture:
#   Management account (aws.management) — delegator, Config recorder
#   Security account  (aws.security)    — delegated admin for GD + SH,
#                                         Config aggregator, SNS + EventBridge
# ═══════════════════════════════════════════════════════════════════════════

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.0"
      configuration_aliases = [aws.management, aws.security]
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════
# KMS KEYS — separate key per service (blast radius isolation)
# ═══════════════════════════════════════════════════════════════════════════

# KMS: AWS Config delivery S3 (management account)
resource "aws_kms_key" "config" {
  provider                = aws.management
  description             = "KMS key for AWS Config delivery S3 bucket encryption"
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableManagementAccountRoot"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.aws_account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowConfigServiceEncrypt"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.aws_account_id }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-config-kms"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "config" {
  provider      = aws.management
  name          = "alias/${var.project_name}-config"
  target_key_id = aws_kms_key.config.key_id
}

# KMS: GuardDuty findings S3 (security account)
resource "aws_kms_key" "guardduty" {
  provider                = aws.security
  description             = "KMS key for GuardDuty findings S3 bucket encryption"
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableSecurityAccountRoot"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.security_account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowGuardDutyEncrypt"
        Effect = "Allow"
        Principal = { Service = "guardduty.amazonaws.com" }
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.security_account_id }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-guardduty-kms"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "guardduty" {
  provider      = aws.security
  name          = "alias/${var.project_name}-guardduty"
  target_key_id = aws_kms_key.guardduty.key_id
}

# KMS: SNS alerts (security account)
resource "aws_kms_key" "sns" {
  provider                = aws.security
  description             = "KMS key for SNS security alerts topic encryption"
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableSecurityAccountRoot"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.security_account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        # EventBridge needs to encrypt when publishing to SNS
        Sid    = "AllowEventBridgeAndSNS"
        Effect = "Allow"
        Principal = {
          Service = [
            "events.amazonaws.com",
            "sns.amazonaws.com"
          ]
        }
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.security_account_id }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-sns-kms"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "sns" {
  provider      = aws.security
  name          = "alias/${var.project_name}-sns-alerts"
  target_key_id = aws_kms_key.sns.key_id
}

# ═══════════════════════════════════════════════════════════════════════════
# GUARDDUTY
# Flow: enable in mgmt → delegate to security → configure org-wide → export findings
# ═══════════════════════════════════════════════════════════════════════════

# Step 1: Enable GuardDuty detector in management account (it becomes a member)
resource "aws_guardduty_detector" "management" {
  provider = aws.management
  enable   = true

  datasources {
    s3_logs { enable = true }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes { enable = true }
      }
    }
  }

  tags = {
    Name        = "${var.project_name}-guardduty-mgmt"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Step 2: Delegate GuardDuty admin to Security account (from management)
resource "aws_guardduty_organization_admin_account" "security" {
  provider         = aws.management
  admin_account_id = var.security_account_id

  depends_on = [aws_guardduty_detector.management]
}

# Step 3: Read the GuardDuty detector that AWS auto-created in Security account
# AWS automatically creates a detector when delegated admin is registered
# We use data source instead of resource to avoid "already exists" error
data "aws_guardduty_detector" "security" {
  provider = aws.security

  depends_on = [aws_guardduty_organization_admin_account.security]
}

# NOTE: aws_guardduty_organization_configuration is intentionally omitted.
# AWS automatically configures org-wide GuardDuty (auto_enable=ALL) when delegated
# admin is registered. Managing it via Terraform causes permission errors regardless
# of which provider is used. AWS SRA pattern: delegation handles this automatically.

# Step 5: S3 bucket for GuardDuty findings export (security account)
# GuardDuty keeps findings only 90 days — S3 export gives us 7-year retention for ISO 27001
resource "aws_s3_bucket" "guardduty_findings" {
  provider      = aws.security
  bucket        = "${var.project_name}-guardduty-findings-${var.security_account_id}"
  force_destroy = var.force_destroy # lab: true, production: false

  tags = {
    Name        = "${var.project_name}-guardduty-findings"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_s3_bucket_versioning" "guardduty_findings" {
  provider = aws.security
  bucket   = aws_s3_bucket.guardduty_findings.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "guardduty_findings" {
  provider = aws.security
  bucket   = aws_s3_bucket.guardduty_findings.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.guardduty.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "guardduty_findings" {
  provider                = aws.security
  bucket                  = aws_s3_bucket.guardduty_findings.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "guardduty_findings" {
  provider = aws.security
  bucket   = aws_s3_bucket.guardduty_findings.id

  rule {
    id     = "guardduty-findings-retention"
    status = "Enabled"
    filter {}

    transition {
      days          = var.s3_transition_ia_days
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = var.s3_transition_glacier_days
      storage_class = "GLACIER"
    }
    expiration {
      days = var.s3_expiration_days # default 7 years — ISO 27001 audit log retention
    }
  }
}

resource "aws_s3_bucket_policy" "guardduty_findings" {
  provider = aws.security
  bucket   = aws_s3_bucket.guardduty_findings.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Deny all non-HTTPS requests
        Sid       = "DenyNonSSLRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:aws:s3:::${var.project_name}-guardduty-findings-${var.security_account_id}",
          "arn:aws:s3:::${var.project_name}-guardduty-findings-${var.security_account_id}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid    = "AllowGuardDutyGetBucketLocation"
        Effect = "Allow"
        Principal = { Service = "guardduty.amazonaws.com" }
        Action   = "s3:GetBucketLocation"
        Resource = "arn:aws:s3:::${var.project_name}-guardduty-findings-${var.security_account_id}"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.security_account_id }
        }
      },
      {
        Sid    = "AllowGuardDutyPutObject"
        Effect = "Allow"
        Principal = { Service = "guardduty.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${var.project_name}-guardduty-findings-${var.security_account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = var.security_account_id
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.guardduty_findings]
}

# Step 6: Export GuardDuty findings to S3 (long-term storage)
resource "aws_guardduty_publishing_destination" "s3" {
  provider        = aws.security
  detector_id     = data.aws_guardduty_detector.security.id
  destination_arn = aws_s3_bucket.guardduty_findings.arn
  kms_key_arn     = aws_kms_key.guardduty.arn

  depends_on = [
    aws_s3_bucket_policy.guardduty_findings,
    aws_kms_key.guardduty
  ]
}

# Step 4: Enable Runtime Monitoring on both detectors.
# GuardDuty.11 (HIGH) — Security Hub checks that Runtime Monitoring is enabled
# for the delegated admin account AND all member accounts.
# Runtime Monitoring monitors process-level activity on EC2, ECS Fargate, and EKS.
# It cannot be set via datasources{} block — requires aws_guardduty_detector_feature.
#
# Sub-features:
#   EKS_ADDON_MANAGEMENT         — auto-deploys GuardDuty security agent to EKS nodes
#   ECS_FARGATE_AGENT_MANAGEMENT — auto-deploys agent to Fargate tasks
#   EC2_AGENT_MANAGEMENT         — auto-deploys agent to EC2 instances via SSM

# Runtime Monitoring — Management account detector
resource "aws_guardduty_detector_feature" "runtime_monitoring_management" {
  provider    = aws.management
  detector_id = aws_guardduty_detector.management.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "ENABLED"
  }

  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = "ENABLED"
  }

  additional_configuration {
    name   = "EC2_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

# Runtime Monitoring — Security account detector (delegated admin)
# Uses data source ID because AWS auto-created this detector on delegation
resource "aws_guardduty_detector_feature" "runtime_monitoring_security" {
  provider    = aws.security
  detector_id = data.aws_guardduty_detector.security.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "ENABLED"
  }

  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = "ENABLED"
  }

  additional_configuration {
    name   = "EC2_AGENT_MANAGEMENT"
    status = "ENABLED"
  }

  depends_on = [data.aws_guardduty_detector.security]
}

# ═══════════════════════════════════════════════════════════════════════════
# SECURITY HUB
# Flow: enable in mgmt → delegate to security → configure org-wide → enable standards
# ═══════════════════════════════════════════════════════════════════════════

# Step 1: Enable Security Hub in management account
resource "aws_securityhub_account" "management" {
  provider                  = aws.management
  enable_default_standards  = false        # we manage standards explicitly below
  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"
}

# Step 2: Delegate Security Hub admin to Security account
resource "aws_securityhub_organization_admin_account" "security" {
  provider         = aws.management
  admin_account_id = var.security_account_id

  depends_on = [aws_securityhub_account.management]
}

# Step 3: Security Hub account in Security account (delegated admin)
# AWS auto-enables Security Hub when delegated admin is registered.
# lifecycle ignore_changes = all prevents "already subscribed" error on re-apply
resource "aws_securityhub_account" "security" {
  provider                  = aws.security
  enable_default_standards  = false
  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"

  lifecycle {
    ignore_changes = all # AWS auto-creates this — we just manage it declaratively
  }

  depends_on = [aws_securityhub_organization_admin_account.security]
}

# Step 4: Configure org-wide auto-enable (new accounts get Security Hub automatically)
resource "aws_securityhub_organization_configuration" "main" {
  provider              = aws.security
  auto_enable           = true
  auto_enable_standards = "NONE" # we control standards explicitly

  depends_on = [aws_securityhub_account.security]
}

# Step 5: Enable security standards (each adds specific controls and findings)

# AWS Foundational Security Best Practices — core AWS security baseline
resource "aws_securityhub_standards_subscription" "fsbp" {
  provider      = aws.security
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_organization_configuration.main]
}

# CIS AWS Foundations Benchmark v1.4.0 — industry standard (maps well to ISO 27001)
resource "aws_securityhub_standards_subscription" "cis" {
  provider      = aws.security
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"

  depends_on = [aws_securityhub_organization_configuration.main]
}

# PCI DSS v3.2.1 — payment card compliance (strong CV addition even without payments)
resource "aws_securityhub_standards_subscription" "pci" {
  provider      = aws.security
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/pci-dss/v/3.2.1"

  depends_on = [aws_securityhub_organization_configuration.main]
}

# ═══════════════════════════════════════════════════════════════════════════
# AWS CONFIG
# Flow: S3 bucket → IAM role → recorder → delivery channel → enable
#       → aggregate authorization → org aggregator in security account
# ═══════════════════════════════════════════════════════════════════════════

# S3 bucket for Config delivery snapshots (management account)
resource "aws_s3_bucket" "config" {
  provider      = aws.management
  bucket        = "${var.project_name}-config-delivery-${var.aws_account_id}"
  force_destroy = var.force_destroy # lab: true, production: false

  tags = {
    Name        = "${var.project_name}-config-delivery"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_s3_bucket_versioning" "config" {
  provider = aws.management
  bucket   = aws_s3_bucket.config.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  provider = aws.management
  bucket   = aws_s3_bucket.config.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.config.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  provider                = aws.management
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  provider = aws.management
  bucket   = aws_s3_bucket.config.id

  rule {
    id     = "config-delivery-retention"
    status = "Enabled"
    filter {}

    transition {
      days          = var.s3_transition_ia_days
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = var.s3_transition_glacier_days
      storage_class = "GLACIER"
    }
    expiration {
      days = var.s3_expiration_days # default 7 years — ISO 27001 audit log retention
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  provider = aws.management
  bucket   = aws_s3_bucket.config.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonSSLRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:aws:s3:::${var.project_name}-config-delivery-${var.aws_account_id}",
          "arn:aws:s3:::${var.project_name}-config-delivery-${var.aws_account_id}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid    = "AllowConfigGetBucketAcl"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::${var.project_name}-config-delivery-${var.aws_account_id}"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.aws_account_id }
        }
      },
      {
        Sid    = "AllowConfigPutObject"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${var.project_name}-config-delivery-${var.aws_account_id}/AWSLogs/${var.aws_account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = var.aws_account_id
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.config]
}

# CIS 3.5: Config must use service-linked role (not a custom IAM role) for resource recording.
# AWS manages this role's permissions automatically — no custom policies needed.
resource "aws_iam_service_linked_role" "config_management" {
  provider         = aws.management
  aws_service_name = "config.amazonaws.com"
  description      = "Service-linked role for AWS Config in management account"

  lifecycle {
    prevent_destroy = true # role may already exist; import if needed
  }
}

# Config recorder — records ALL supported resource types including global (IAM, etc.)
resource "aws_config_configuration_recorder" "main" {
  provider = aws.management
  name     = "${var.project_name}-config-recorder"
  role_arn = aws_iam_service_linked_role.config_management.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true # IAM, Route53 — global resources
  }

  depends_on = [aws_iam_service_linked_role.config_management]
}

# Config delivery channel — where snapshots and change notifications go
resource "aws_config_delivery_channel" "main" {
  provider       = aws.management
  name           = "${var.project_name}-config-delivery"
  s3_bucket_name = aws_s3_bucket.config.id
  s3_kms_key_arn = aws_kms_key.config.arn

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Enable the recorder (separate resource from recorder definition — Terraform quirk)
resource "aws_config_configuration_recorder_status" "main" {
  provider   = aws.management
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# Authorize Security account to aggregate Config data from Management account
resource "aws_config_aggregate_authorization" "to_security" {
  provider   = aws.management
  account_id = var.security_account_id
  region     = var.aws_region

  tags = {
    Name        = "${var.project_name}-config-aggregate-auth"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Register Security account as delegated administrator for AWS Config
# Without this, Config aggregator in security account gets OrganizationAccessDeniedException
resource "aws_organizations_delegated_administrator" "config" {
  provider          = aws.management
  account_id        = var.security_account_id
  service_principal = "config.amazonaws.com"

  depends_on = [aws_config_configuration_recorder_status.main]
}

# IAM role for Config aggregator in security account
resource "aws_iam_role" "config_aggregator" {
  provider = aws.security
  name     = "${var.project_name}-config-aggregator-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.security_account_id }
      }
    }]
  })

  tags = {
    Name        = "${var.project_name}-config-aggregator-role"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# AWS managed policy for org-level Config aggregation
resource "aws_iam_role_policy_attachment" "config_aggregator" {
  provider   = aws.security
  role       = aws_iam_role.config_aggregator.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
}

# Config aggregator in Security account — single pane of glass for the whole org
resource "aws_config_configuration_aggregator" "org" {
  provider = aws.security
  name     = "${var.project_name}-config-org-aggregator"

  organization_aggregation_source {
    role_arn    = aws_iam_role.config_aggregator.arn
    all_regions = true
  }

  tags = {
    Name        = "${var.project_name}-config-org-aggregator"
    Environment = var.environment
    ManagedBy   = "terraform"
  }

  depends_on = [
    aws_organizations_delegated_administrator.config,
    aws_config_aggregate_authorization.to_security,
    aws_iam_role_policy_attachment.config_aggregator
  ]
}

# ═══════════════════════════════════════════════════════════════════════════
# AWS CONFIG — SECURITY ACCOUNT
# CIS 3.5 checks each account independently. The aggregator in the Security
# account is NOT a substitute for a local recorder — each account needs its own.
# ═══════════════════════════════════════════════════════════════════════════

# KMS key for Config delivery S3 in Security account
resource "aws_kms_key" "config_security" {
  provider                = aws.security
  description             = "KMS key for AWS Config delivery S3 bucket encryption (security account)"
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableSecurityAccountRoot"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.security_account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowConfigServiceEncrypt"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.security_account_id }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-config-security-kms"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "config_security" {
  provider      = aws.security
  name          = "alias/${var.project_name}-config-security"
  target_key_id = aws_kms_key.config_security.key_id
}

# S3 bucket for Config delivery snapshots (security account)
resource "aws_s3_bucket" "config_security" {
  provider      = aws.security
  bucket        = "${var.project_name}-config-delivery-${var.security_account_id}"
  force_destroy = var.force_destroy

  tags = {
    Name        = "${var.project_name}-config-delivery-security"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_s3_bucket_versioning" "config_security" {
  provider = aws.security
  bucket   = aws_s3_bucket.config_security.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_security" {
  provider = aws.security
  bucket   = aws_s3_bucket.config_security.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.config_security.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "config_security" {
  provider                = aws.security
  bucket                  = aws_s3_bucket.config_security.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "config_security" {
  provider = aws.security
  bucket   = aws_s3_bucket.config_security.id

  rule {
    id     = "config-delivery-security-retention"
    status = "Enabled"
    filter {}

    transition {
      days          = var.s3_transition_ia_days
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = var.s3_transition_glacier_days
      storage_class = "GLACIER"
    }
    expiration {
      days = var.s3_expiration_days # 7 years — ISO 27001 audit log retention
    }
  }
}

resource "aws_s3_bucket_policy" "config_security" {
  provider = aws.security
  bucket   = aws_s3_bucket.config_security.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonSSLRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:aws:s3:::${var.project_name}-config-delivery-${var.security_account_id}",
          "arn:aws:s3:::${var.project_name}-config-delivery-${var.security_account_id}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid    = "AllowConfigGetBucketAcl"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::${var.project_name}-config-delivery-${var.security_account_id}"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.security_account_id }
        }
      },
      {
        Sid    = "AllowConfigPutObject"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${var.project_name}-config-delivery-${var.security_account_id}/AWSLogs/${var.security_account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = var.security_account_id
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.config_security]
}

# CIS 3.5: Service-linked role for AWS Config in Security account
resource "aws_iam_service_linked_role" "config_security" {
  provider         = aws.security
  aws_service_name = "config.amazonaws.com"
  description      = "Service-linked role for AWS Config in security account"

  lifecycle {
    prevent_destroy = true # role may already exist; import if needed
  }
}

# Config recorder in Security account
resource "aws_config_configuration_recorder" "security" {
  provider = aws.security
  name     = "${var.project_name}-config-recorder-security"
  role_arn = aws_iam_service_linked_role.config_security.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = false # global resources only recorded once (management)
  }

  depends_on = [aws_iam_service_linked_role.config_security]
}

# Config delivery channel in Security account
resource "aws_config_delivery_channel" "security" {
  provider       = aws.security
  name           = "${var.project_name}-config-delivery-security"
  s3_bucket_name = aws_s3_bucket.config_security.id
  s3_kms_key_arn = aws_kms_key.config_security.arn

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.security]
}

# Enable the recorder in Security account
resource "aws_config_configuration_recorder_status" "security" {
  provider   = aws.security
  name       = aws_config_configuration_recorder.security.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.security]
}

# ═══════════════════════════════════════════════════════════════════════════
# IAM ACCESS ANALYZER
# Detects unintended public or cross-account access to resources
# Organization type = analyzes all accounts in the org, not just management
# ═══════════════════════════════════════════════════════════════════════════

resource "aws_accessanalyzer_analyzer" "org" {
  provider      = aws.management
  analyzer_name = "${var.project_name}-org-access-analyzer"
  type          = "ORGANIZATION"

  tags = {
    Name        = "${var.project_name}-org-access-analyzer"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ═══════════════════════════════════════════════════════════════════════════
# SNS + EVENTBRIDGE ALERTING
# Security Hub and GuardDuty findings → EventBridge → SNS → Email
# Lives in Security account — that's where the aggregated findings are
# ═══════════════════════════════════════════════════════════════════════════

resource "aws_sns_topic" "security_alerts" {
  provider          = aws.security
  name              = "${var.project_name}-security-alerts"
  kms_master_key_id = aws_kms_key.sns.arn

  tags = {
    Name        = "${var.project_name}-security-alerts"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Email subscription — confirm via email after first apply
resource "aws_sns_topic_subscription" "alert_email" {
  provider  = aws.security
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# SNS topic policy — only owner and EventBridge can publish
resource "aws_sns_topic_policy" "security_alerts" {
  provider = aws.security
  arn      = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowTopicOwner"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.security_account_id}:root" }
        Action = [
          "sns:Publish",
          "sns:GetTopicAttributes",
          "sns:SetTopicAttributes",
          "sns:AddPermission",
          "sns:RemovePermission",
          "sns:DeleteTopic",
          "sns:ListSubscriptionsByTopic",
          "sns:Subscribe"
        ]
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.security_account_id }
        }
      }
    ]
  })
}

# EventBridge rule: Security Hub HIGH/CRITICAL findings
# Filter: only NEW (not suppressed/resolved) ACTIVE findings
resource "aws_cloudwatch_event_rule" "securityhub_findings" {
  provider    = aws.security
  name        = "${var.project_name}-securityhub-critical-findings"
  description = "Alert on HIGH and CRITICAL Security Hub findings (new + active only)"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity    = { Label = ["HIGH", "CRITICAL"] }
        Workflow    = { Status = ["NEW"] }
        RecordState = ["ACTIVE"]
      }
    }
  })

  tags = {
    Name        = "${var.project_name}-securityhub-findings"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_cloudwatch_event_target" "securityhub_to_sns" {
  provider  = aws.security
  rule      = aws_cloudwatch_event_rule.securityhub_findings.name
  target_id = "SecurityHubToSNS"
  arn       = aws_sns_topic.security_alerts.arn

  input_transformer {
    input_paths = {
      account     = "$.detail.findings[0].AwsAccountId"
      title       = "$.detail.findings[0].Title"
      severity    = "$.detail.findings[0].Severity.Label"
      description = "$.detail.findings[0].Description"
      region      = "$.region"
      time        = "$.time"
      remediation = "$.detail.findings[0].Remediation.Recommendation.Text"
    }
    input_template = <<-EOT
      "SECURITY HUB ALERT"
      "Severity : <severity>"
      "Account  : <account>"
      "Region   : <region>"
      "Time     : <time>"
      "Title    : <title>"
      "Details  : <description>"
      "Fix      : <remediation>"
    EOT
  }
}

# EventBridge rule: GuardDuty severity 7+ (High = 7-8.9, Critical = 9-10)
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  provider    = aws.security
  name        = "${var.project_name}-guardduty-high-critical-findings"
  description = "Alert on GuardDuty findings with severity >= 7 (High/Critical)"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
    }
  })

  tags = {
    Name        = "${var.project_name}-guardduty-findings"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_cloudwatch_event_target" "guardduty_to_sns" {
  provider  = aws.security
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "GuardDutyToSNS"
  arn       = aws_sns_topic.security_alerts.arn

  input_transformer {
    input_paths = {
      account     = "$.detail.accountId"
      title       = "$.detail.title"
      severity    = "$.detail.severity"
      description = "$.detail.description"
      region      = "$.region"
      time        = "$.time"
      type        = "$.detail.type"
    }
    input_template = <<-EOT
      "GUARDDUTY ALERT"
      "Severity : <severity>/10"
      "Account  : <account>"
      "Region   : <region>"
      "Time     : <time>"
      "Type     : <type>"
      "Title    : <title>"
      "Details  : <description>"
    EOT
  }
}

# ═══════════════════════════════════════════════════════════════════════════
# SSM DOCUMENTS
# SSM.7 — Block public sharing of SSM documents at account level
# ═══════════════════════════════════════════════════════════════════════════

# Management account — block SSM document public sharing
resource "aws_ssm_service_setting" "block_public_sharing_management" {
  provider      = aws.management
  setting_id    = "/ssm/documents/console/public-sharing-permission"
  setting_value = "Disable"
}

# Security account — block SSM document public sharing
resource "aws_ssm_service_setting" "block_public_sharing_security" {
  provider      = aws.security
  setting_id    = "/ssm/documents/console/public-sharing-permission"
  setting_value = "Disable"
}

# ═══════════════════════════════════════════════════════════════════════════
# AMAZON INSPECTOR V2
# Inspector.2 — Enable Inspector v2 with ECR and EC2 scanning
# ═══════════════════════════════════════════════════════════════════════════

# Enable Inspector v2 with ECR scanning — Management account
resource "aws_inspector2_enabler" "management" {
  provider       = aws.management
  account_ids    = [var.aws_account_id]
  resource_types = ["ECR", "EC2"]
}

# Enable Inspector v2 with ECR scanning — Security account
resource "aws_inspector2_enabler" "security" {
  provider       = aws.security
  account_ids    = [var.security_account_id]
  resource_types = ["ECR", "EC2"]
}
