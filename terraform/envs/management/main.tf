module "organizations" {
  source = "../../modules/organizations"

  aws_region      = var.aws_region
  project_name    = var.project_name
  member_accounts = var.member_accounts
  tags            = var.tags
}

module "cloudtrail" {
  source = "../../modules/cloudtrail"

  aws_account_id  = var.aws_account_id
  organization_id = module.organizations.org_id
  project_name    = var.project_name
  environment     = var.environment
  region          = var.aws_region

  # Extracted variables — configurable from terraform.tfvars
  force_destroy                 = var.force_destroy
  kms_deletion_window_days      = var.kms_deletion_window_days
  cloudtrail_log_retention_days = var.cloudtrail_log_retention_days
  s3_transition_ia_days         = var.s3_transition_ia_days
  s3_transition_glacier_days    = var.s3_transition_glacier_days
  s3_expiration_days            = var.s3_expiration_days
}

module "security" {
  source = "../../modules/security"

  aws_account_id      = var.aws_account_id
  security_account_id = var.security_account_id
  aws_region          = var.aws_region
  project_name        = var.project_name
  environment         = var.environment
  org_id              = module.organizations.org_id
  alert_email         = var.alert_email

  # Extracted variables — configurable from terraform.tfvars
  force_destroy              = var.force_destroy
  kms_deletion_window_days   = var.kms_deletion_window_days
  s3_transition_ia_days      = var.s3_transition_ia_days
  s3_transition_glacier_days = var.s3_transition_glacier_days
  s3_expiration_days         = var.s3_expiration_days

  # Pass both providers explicitly — module uses configuration_aliases
  providers = {
    aws.management = aws
    aws.security   = aws.security
  }

  # Organizations must exist before we can delegate admin accounts
  depends_on = [module.organizations]
}

module "alerting" {
  source = "../../modules/alerting"

  aws_account_id            = var.aws_account_id
  aws_region                = var.aws_region
  project_name              = var.project_name
  environment               = var.environment
  ops_alert_email           = var.ops_alert_email
  cloudtrail_log_group_name = module.cloudtrail.log_group_name
  dr_region                 = var.dr_region
  tags                      = var.tags

  # CloudTrail log group must exist before we can attach metric filters to it.
  depends_on = [module.cloudtrail]
}

module "backup" {
  source = "../../modules/backup"

  aws_account_id = var.aws_account_id
  aws_region     = var.aws_region
  dr_region      = var.dr_region
  project_name   = var.project_name
  environment    = var.environment

  # Vault Lock — keep false for day-to-day lab work
  # Set to true ONLY when you want to demonstrate ISO 27001 A.12.3 WORM compliance
  # WARNING: 3-day grace period, then the lock is permanent and cannot be removed
  enable_vault_lock             = var.enable_vault_lock
  vault_lock_min_retention_days = 7
  vault_lock_max_retention_days = 365
  vault_lock_changeable_for_days = 5

  # Backup retention windows (short for cost-efficient lab)
  daily_retention_days  = var.daily_retention_days
  weekly_retention_days = var.weekly_retention_days
  dr_copy_retention_days = var.dr_copy_retention_days

  # Extracted variables — configurable from terraform.tfvars
  force_destroy            = var.force_destroy
  kms_deletion_window_days = var.kms_deletion_window_days

  tags = var.tags

  # Pass both providers — primary region and DR region
  providers = {
    aws    = aws
    aws.dr = aws.dr
  }
}
