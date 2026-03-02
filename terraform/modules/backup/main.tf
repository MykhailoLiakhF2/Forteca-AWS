# ─────────────────────────────────────────────────────────────────────────────
# Module: backup — main
# Purpose: AWS Backup Vault with Vault Lock (WORM), cross-region DR replication,
#          backup plans and selections for ISO 27001 A.12.3 compliance
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
      # Two provider instances are needed:
      #   aws          → eu-north-1 (primary region, backup vault)
      #   aws.dr       → eu-west-1  (disaster recovery vault for cross-region copies)
      # The calling module (envs/management/main.tf) must pass both.
      configuration_aliases = [aws.dr]
    }
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. KMS KEY — Backup Vault Encryption (primary region)
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_kms_key" "backup" {
  # Human-readable description shown in KMS console
  description = "CMK for Forteca AWS Backup vault encryption — ${var.environment}"

  # Automatic annual key rotation — best practice, required by ISO 27001 A.10.1
  enable_key_rotation = true

  # How long (in days) KMS waits before permanently deleting a key scheduled
  # for deletion. Minimum is 7 days. This safety window lets you cancel if
  # you accidentally schedule deletion.
  deletion_window_in_days = var.kms_deletion_window_days

  # KMS key policy — defines WHO can use this key
  # We need to allow:
  #   a) The management account root (required for all KMS keys — cannot be removed)
  #   b) AWS Backup service principal (so it can encrypt/decrypt recovery points)
  #   c) IAM entities in the account (so our backup IAM role can use the key)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # Statement 1: Root account has full key management access
      # This is a mandatory statement — without it, the key becomes unmanageable
      {
        Sid    = "EnableRootAccountManagement"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.aws_account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },

      # Statement 2: AWS Backup service can use this key to encrypt/decrypt backups
      # The Backup service assumes an IAM role when running jobs, but the KMS key
      # policy must also explicitly allow the service principal.
      {
        Sid    = "AllowBackupServiceEncryption"
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey", # Backup uses this to get an encrypted data key
          "kms:Decrypt",         # Backup uses this to restore (decrypt) data
          "kms:DescribeKey"      # Backup uses this to validate the key
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, {
    Name    = "${var.project_name}-backup-cmk"
    Purpose = "backup-vault-encryption"
  })
}

# Friendly alias so you can find this key by name in the KMS console
resource "aws_kms_alias" "backup" {
  # alias/ prefix is required by AWS
  name          = "alias/${var.project_name}-backup"
  target_key_id = aws_kms_key.backup.key_id
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. KMS KEY — DR Vault Encryption (eu-west-1)
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_kms_key" "backup_dr" {
  # This key is created in eu-west-1 — the provider alias handles that
  provider = aws.dr

  description             = "CMK for Forteca AWS Backup DR vault encryption — ${var.environment}"
  enable_key_rotation     = true
  deletion_window_in_days = var.kms_deletion_window_days

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccountManagement"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.aws_account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowBackupServiceEncryption"
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, {
    Name    = "${var.project_name}-backup-cmk-dr"
    Purpose = "backup-vault-encryption-dr"
  })
}

resource "aws_kms_alias" "backup_dr" {
  provider      = aws.dr
  name          = "alias/${var.project_name}-backup-dr"
  target_key_id = aws_kms_key.backup_dr.key_id
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. PRIMARY BACKUP VAULT (eu-north-1)
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_backup_vault" "primary" {
  name        = "${var.project_name}-backup-vault-primary"
  kms_key_arn = aws_kms_key.backup.arn

  # force_destroy = true allows Terraform to delete the vault even if it contains
  # recovery points. For lab this is essential — you want to be able to destroy
  # everything with `terraform destroy`. In production set this to false.
  force_destroy = var.force_destroy # lab: true, production: false

  tags = merge(var.tags, {
    Name    = "${var.project_name}-backup-vault-primary"
    Purpose = "primary-backup-storage"
    Region  = var.aws_region
  })
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. VAULT LOCK — WORM (Write Once Read Many)
# ─────────────────────────────────────────────────────────────────────────────
# Vault Lock (COMPLIANCE mode) prevents deletion of recovery points before 
# minimum retention period expires. Complies with ISO 27001 A.12.3.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_backup_vault_lock_configuration" "primary" {
  # Only create this resource when enable_vault_lock = true
  # count = 0 means the resource won't be created at all (lab default)
  count = var.enable_vault_lock ? 1 : 0

  backup_vault_name = aws_backup_vault.primary.name

  # Minimum retention: no backup can be deleted before 7 days
  # AWS Backup will reject lifecycle rules shorter than this
  min_retention_days = var.vault_lock_min_retention_days

  # Maximum retention: no backup can be retained longer than 365 days
  # Prevents accidental storage cost overruns
  max_retention_days = var.vault_lock_max_retention_days

  # Grace period: you have this many days to remove the lock after creation.
  # After this window expires, the lock is PERMANENT and CANNOT BE REMOVED.
  # AWS minimum value is 3 days. Set to 3 for maximum lab flexibility.
  changeable_for_days = var.vault_lock_changeable_for_days
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. DR BACKUP VAULT (eu-west-1)
# ─────────────────────────────────────────────────────────────────────────────
# Disaster Recovery vault in secondary region. Complies with ISO 27001 A.17.1.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_backup_vault" "dr" {
  # Use the DR provider — this creates the vault in eu-west-1
  provider = aws.dr

  name        = "${var.project_name}-backup-vault-dr"
  kms_key_arn = aws_kms_key.backup_dr.arn

  force_destroy = var.force_destroy # lab: true, production: false

  tags = merge(var.tags, {
    Name    = "${var.project_name}-backup-vault-dr"
    Purpose = "disaster-recovery-backup-storage"
    Region  = var.dr_region
  })
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. IAM ROLE — AWS Backup Service Role
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_iam_role" "backup" {
  name        = "${var.project_name}-backup-service-role"
  description = "IAM role assumed by AWS Backup service to perform backup and restore jobs"

  # Trust policy: only AWS Backup service can assume this role
  # Without this, no service or user could use the role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBackupServiceToAssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, {
    Name    = "${var.project_name}-backup-service-role"
    Purpose = "aws-backup-service-role"
  })
}

# AWS provides managed policies for Backup — we attach both:
#   AWSBackupServiceRolePolicyForBackup    → permissions to CREATE backups (snapshots, copies)
#   AWSBackupServiceRolePolicyForRestores  → permissions to RESTORE from backups
# Attaching both to one role keeps things simple for a lab environment.
# In production you might separate backup-only and restore-only roles.

resource "aws_iam_role_policy_attachment" "backup_policy" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "restore_policy" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

# ─────────────────────────────────────────────────────────────────────────────
# 7. BACKUP PLAN — Schedule and Retention Rules
# ─────────────────────────────────────────────────────────────────────────────
# Defines daily and weekly backup rules, retention schedules, and cross-region
# copy configurations for the DR vault.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_backup_plan" "forteca" {
  name = "${var.project_name}-backup-plan"

  # ── Rule 1: Daily Backups ──────────────────────────────────────────────────
  rule {
    rule_name         = "daily-backup"
    target_vault_name = aws_backup_vault.primary.name

    # Cron expression (AWS Backup uses cron in UTC):
    # cron(Minutes Hours DayOfMonth Month DayOfWeek Year)
    # cron(0 2 * * ? *) = Every day at 02:00 UTC
    # The ? in DayOfWeek means "no specific value" (required when DayOfMonth is set to *)
    schedule = var.backup_window_start # default: cron(0 2 * * ? *)

    # AWS Backup waits up to this many minutes after schedule before declaring
    # the job missed. 60 minutes = 1 hour slack.
    start_window = 60

    # Maximum time (minutes) the backup job is allowed to run.
    # If it takes longer, AWS Backup marks it as FAILED.
    # 240 minutes = 4 hours — reasonable for most workloads.
    completion_window = var.backup_window_complete_within_hours * 60

    # Lifecycle defines how long to keep this backup
    lifecycle {
      # cold_storage_after: move to cold storage (Glacier) after N days.
      # Not set here — for a 7-day daily backup, cold storage isn't cost-effective.
      # If you had 90+ day retention, you'd add: cold_storage_after = 30

      # delete_after: permanently delete the recovery point after N days
      delete_after = var.daily_retention_days
    }

    # ── Cross-Region Copy Action ─────────────────────────────────────────────
    # After each successful backup, copy the recovery point to the DR vault.
    # This is what makes this a true DR setup — data exists in TWO regions.
    copy_action {
      # ARN of the destination vault (in eu-west-1)
      destination_vault_arn = aws_backup_vault.dr.arn

      # DR copies can have their own retention (different from primary)
      lifecycle {
        delete_after = var.dr_copy_retention_days
      }
    }
  }

  # ── Rule 2: Weekly Backups ─────────────────────────────────────────────────
  rule {
    rule_name         = "weekly-backup"
    target_vault_name = aws_backup_vault.primary.name

    # cron(0 3 ? * 1 *) = Every Sunday at 03:00 UTC
    # Day 1 = Sunday in AWS cron syntax
    # ? in DayOfMonth means "no specific day" (required when DayOfWeek is specified)
    schedule         = "cron(0 3 ? * 1 *)"
    start_window     = 60
    completion_window = var.backup_window_complete_within_hours * 60

    lifecycle {
      delete_after = var.weekly_retention_days # 30 days = 4-5 weekly backups kept
    }

    copy_action {
      destination_vault_arn = aws_backup_vault.dr.arn
      lifecycle {
        delete_after = var.dr_copy_retention_days
      }
    }
  }

  tags = merge(var.tags, {
    Name    = "${var.project_name}-backup-plan"
    Purpose = "backup-schedule-and-retention"
  })
}

# ─────────────────────────────────────────────────────────────────────────────
# 8. BACKUP SELECTION — Which Resources to Back Up
# ─────────────────────────────────────────────────────────────────────────────
# Targets all resources with the tag Backup="true".
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_backup_selection" "forteca" {
  name          = "${var.project_name}-backup-selection"
  iam_role_arn  = aws_iam_role.backup.arn
  plan_id       = aws_backup_plan.forteca.id

  # Tag-based selection: back up any resource where tag "Backup" = "true"
  # This means when you create an EC2 or RDS later, just add the tag and
  # it will be automatically included in daily + weekly backups.
  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "true"
  }
}
