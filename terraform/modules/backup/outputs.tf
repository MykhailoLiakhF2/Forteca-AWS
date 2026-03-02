# ─────────────────────────────────────────────────────────────────────────────
# Module: backup — outputs
# Purpose: Export key resource identifiers for use in envs/management/outputs.tf
#          and for the project_status.md documentation
# ─────────────────────────────────────────────────────────────────────────────

# ─── KMS Keys ─────────────────────────────────────────────────────────────────

output "backup_kms_key_arn" {
  description = "ARN of the KMS key used for primary backup vault encryption"
  value       = aws_kms_key.backup.arn
}

output "backup_kms_key_arn_dr" {
  description = "ARN of the KMS key used for DR backup vault encryption (eu-west-1)"
  value       = aws_kms_key.backup_dr.arn
}

# ─── Backup Vaults ────────────────────────────────────────────────────────────

output "backup_vault_primary_name" {
  description = "Name of the primary backup vault (eu-north-1)"
  value       = aws_backup_vault.primary.name
}

output "backup_vault_primary_arn" {
  description = "ARN of the primary backup vault (eu-north-1)"
  value       = aws_backup_vault.primary.arn
}

output "backup_vault_dr_name" {
  description = "Name of the DR backup vault (eu-west-1)"
  value       = aws_backup_vault.dr.name
}

output "backup_vault_dr_arn" {
  description = "ARN of the DR backup vault (eu-west-1)"
  value       = aws_backup_vault.dr.arn
}

# ─── Vault Lock ───────────────────────────────────────────────────────────────

output "vault_lock_enabled" {
  description = "Whether Vault Lock (WORM) is enabled on the primary vault"
  value       = var.enable_vault_lock
}

# ─── Backup Plan ──────────────────────────────────────────────────────────────

output "backup_plan_id" {
  description = "ID of the Forteca backup plan"
  value       = aws_backup_plan.forteca.id
}

output "backup_plan_arn" {
  description = "ARN of the Forteca backup plan"
  value       = aws_backup_plan.forteca.arn
}

output "backup_plan_version" {
  description = "Version of the backup plan (increments on each update)"
  value       = aws_backup_plan.forteca.version
}

# ─── IAM Role ─────────────────────────────────────────────────────────────────

output "backup_iam_role_arn" {
  description = "ARN of the IAM role used by AWS Backup service"
  value       = aws_iam_role.backup.arn
}
