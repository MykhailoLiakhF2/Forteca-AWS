# ═══════════════════════════════════════════════════════════════════════════
# AWS Config Rules — ISO 27001 Compliance Baseline
#
# All rules run in the Management account where the Config recorder is.
# The Config aggregator in Security account will show a consolidated view.
#
# ISO 27001 control references included in descriptions for audit evidence.
# ═══════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────
# IAM — Identity & Access Management
# ISO 27001: A.9 — Access Control
# ───────────────────────────────────────────

# MFA must be enabled for all IAM users with console password
resource "aws_config_config_rule" "mfa_enabled_for_iam_console" {
  provider    = aws.management
  name        = "${var.project_name}-mfa-enabled-iam-console"
  description = "ISO 27001 A.9.4: MFA must be enabled for all IAM users with console access"

  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Root account must have MFA enabled
resource "aws_config_config_rule" "root_account_mfa_enabled" {
  provider    = aws.management
  name        = "${var.project_name}-root-account-mfa-enabled"
  description = "ISO 27001 A.9.4: Root account must have MFA enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Root account must use hardware MFA (virtual MFA not sufficient for root)
resource "aws_config_config_rule" "root_hardware_mfa" {
  provider    = aws.management
  name        = "${var.project_name}-root-hardware-mfa"
  description = "ISO 27001 A.9.4: Root account must use hardware MFA device"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_HARDWARE_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Root account must not have active access keys (root should never use API)
resource "aws_config_config_rule" "root_no_access_key" {
  provider    = aws.management
  name        = "${var.project_name}-root-no-access-key"
  description = "ISO 27001 A.9.2: Root account must not have active API access keys"

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# IAM users must not have policies attached directly — use groups/roles
resource "aws_config_config_rule" "iam_user_no_inline_policies" {
  provider    = aws.management
  name        = "${var.project_name}-iam-user-no-inline-policies"
  description = "ISO 27001 A.9.2: IAM users must not have inline policies (use groups/roles instead)"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_NO_POLICIES_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Password policy must meet security requirements
resource "aws_config_config_rule" "iam_password_policy" {
  provider    = aws.management
  name        = "${var.project_name}-iam-password-policy"
  description = "ISO 27001 A.9.4: IAM password policy must meet complexity and rotation requirements"

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  input_parameters = jsonencode({
    RequireUppercaseCharacters = "true"
    RequireLowercaseCharacters = "true"
    RequireSymbols             = "true"
    RequireNumbers             = "true"
    MinimumPasswordLength      = "14"
    PasswordReusePrevention    = "24"
    MaxPasswordAge             = "90"
  })

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Access keys must be rotated within 90 days
resource "aws_config_config_rule" "access_keys_rotated" {
  provider    = aws.management
  name        = "${var.project_name}-access-keys-rotated-90d"
  description = "ISO 27001 A.9.4: IAM access keys must be rotated within 90 days"

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }

  input_parameters = jsonencode({
    maxAccessKeyAge = "90"
  })

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Users that haven't used credentials in 90 days should be disabled
resource "aws_config_config_rule" "unused_credentials" {
  provider    = aws.management
  name        = "${var.project_name}-iam-unused-credentials-90d"
  description = "ISO 27001 A.9.2: IAM credentials unused for 90+ days must be disabled"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
  }

  input_parameters = jsonencode({
    maxCredentialUsageAge = "90"
  })

  depends_on = [aws_config_configuration_recorder_status.main]
}

# ───────────────────────────────────────────
# Logging & Audit Trail
# ISO 27001: A.12.4 — Logging and Monitoring
# ───────────────────────────────────────────

# CloudTrail must be enabled
resource "aws_config_config_rule" "cloudtrail_enabled" {
  provider    = aws.management
  name        = "${var.project_name}-cloudtrail-enabled"
  description = "ISO 27001 A.12.4: CloudTrail must be enabled and logging"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CloudTrail logs must be encrypted with KMS
resource "aws_config_config_rule" "cloudtrail_encryption" {
  provider    = aws.management
  name        = "${var.project_name}-cloudtrail-kms-encryption"
  description = "ISO 27001 A.10.1: CloudTrail logs must be encrypted with KMS CMK"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CloudTrail log file integrity validation must be enabled
resource "aws_config_config_rule" "cloudtrail_log_file_validation" {
  provider    = aws.management
  name        = "${var.project_name}-cloudtrail-log-file-validation"
  description = "ISO 27001 A.12.4: CloudTrail log file validation must be enabled (tamper detection)"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# ───────────────────────────────────────────
# S3 — Data at Rest & Access Control
# ISO 27001: A.10.1, A.13.1
# ───────────────────────────────────────────

# S3 buckets must not allow public read access
resource "aws_config_config_rule" "s3_no_public_read" {
  provider    = aws.management
  name        = "${var.project_name}-s3-no-public-read"
  description = "ISO 27001 A.13.1: S3 buckets must not allow public read access"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# S3 buckets must not allow public write access
resource "aws_config_config_rule" "s3_no_public_write" {
  provider    = aws.management
  name        = "${var.project_name}-s3-no-public-write"
  description = "ISO 27001 A.13.1: S3 buckets must not allow public write access"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# S3 buckets must have server-side encryption enabled
resource "aws_config_config_rule" "s3_encryption_enabled" {
  provider    = aws.management
  name        = "${var.project_name}-s3-encryption-enabled"
  description = "ISO 27001 A.10.1: S3 buckets must have server-side encryption enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# S3 buckets must enforce SSL (deny HTTP requests)
resource "aws_config_config_rule" "s3_ssl_requests_only" {
  provider    = aws.management
  name        = "${var.project_name}-s3-ssl-requests-only"
  description = "ISO 27001 A.13.2: S3 bucket policies must deny non-SSL (HTTP) requests"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# ───────────────────────────────────────────
# Encryption — Data at Rest
# ISO 27001: A.10.1 — Cryptographic Controls
# ───────────────────────────────────────────

# EBS volumes must be encrypted
resource "aws_config_config_rule" "ebs_volumes_encrypted" {
  provider    = aws.management
  name        = "${var.project_name}-ebs-volumes-encrypted"
  description = "ISO 27001 A.10.1: EBS volumes must be encrypted"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# RDS database instances must have storage encryption enabled
resource "aws_config_config_rule" "rds_storage_encrypted" {
  provider    = aws.management
  name        = "${var.project_name}-rds-storage-encrypted"
  description = "ISO 27001 A.10.1: RDS instances must have storage encryption enabled"

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# KMS keys must have rotation enabled
resource "aws_config_config_rule" "kms_key_rotation_enabled" {
  provider    = aws.management
  name        = "${var.project_name}-kms-key-rotation-enabled"
  description = "ISO 27001 A.10.1: KMS customer-managed keys must have automatic rotation enabled"

  source {
    owner             = "AWS"
    source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# ───────────────────────────────────────────
# Network — Security Groups & VPC
# ISO 27001: A.13.1 — Network Controls
# ───────────────────────────────────────────

# VPC default security group must not allow any inbound or outbound traffic
resource "aws_config_config_rule" "vpc_default_sg_closed" {
  provider    = aws.management
  name        = "${var.project_name}-vpc-default-sg-closed"
  description = "ISO 27001 A.13.1: VPC default security group must restrict all traffic"

  source {
    owner             = "AWS"
    source_identifier = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# SSH (port 22) must not be open to the world from security groups
resource "aws_config_config_rule" "restricted_ssh" {
  provider    = aws.management
  name        = "${var.project_name}-restricted-ssh"
  description = "ISO 27001 A.13.1: Security groups must not allow unrestricted SSH access (0.0.0.0/0)"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = jsonencode({
    blockedPort1 = "22"
  })

  depends_on = [aws_config_configuration_recorder_status.main]
}

# RDP (port 3389) must not be open to the world
resource "aws_config_config_rule" "restricted_rdp" {
  provider    = aws.management
  name        = "${var.project_name}-restricted-rdp"
  description = "ISO 27001 A.13.1: Security groups must not allow unrestricted RDP access (0.0.0.0/0)"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = jsonencode({
    blockedPort1 = "3389"
  })

  depends_on = [aws_config_configuration_recorder_status.main]
}

# ───────────────────────────────────────────
# Security Services — Detective Controls
# ISO 27001: A.12.6 — Technical Vulnerability Management
# ───────────────────────────────────────────

# GuardDuty must be enabled across the organization
resource "aws_config_config_rule" "guardduty_enabled_centralized" {
  provider    = aws.management
  name        = "${var.project_name}-guardduty-enabled-centralized"
  description = "ISO 27001 A.12.6: GuardDuty must be enabled with centralized admin account"

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }

  depends_on = [
    aws_config_configuration_recorder_status.main,
    aws_guardduty_organization_admin_account.security
  ]
}

# Security Hub must be enabled
resource "aws_config_config_rule" "securityhub_enabled" {
  provider    = aws.management
  name        = "${var.project_name}-securityhub-enabled"
  description = "ISO 27001 A.12.6: Security Hub must be enabled for centralized finding aggregation"

  source {
    owner             = "AWS"
    source_identifier = "SECURITYHUB_ENABLED"
  }

  depends_on = [
    aws_config_configuration_recorder_status.main,
    aws_securityhub_organization_configuration.main
  ]
}
