terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "forteca-tfstate-mgmt"
    key            = "management/organizations/terraform.tfstate"
    region         = "eu-north-1"
    dynamodb_table = "forteca-tfstate-lock"
    encrypt        = true
    profile        = "forteca-management"
  }
}

# Default provider — Management account (runs Terraform, owns Organizations)
provider "aws" {
  region  = var.aws_region
  profile = "forteca-management"
}

# Security account provider — assumes OrganizationAccountAccessRole
# This role is automatically created by AWS Organizations for all member accounts
# Management account has AdministratorAccess → can assume this role without extra setup
provider "aws" {
  alias   = "security"
  region  = var.aws_region
  profile = "forteca-management" # same profile — STS does the cross-account switch

  assume_role {
    role_arn     = "arn:aws:iam::${var.security_account_id}:role/OrganizationAccountAccessRole"
    session_name = "TerraformSecurityModule"
  }
}

# DR (Disaster Recovery) provider — same management account, different region
# AWS Backup cross-region copies need a provider in the destination region.
# No cross-account switch here — the DR vault lives in the management account
# but in eu-west-1 (Ireland) as a geographically separate recovery target.
provider "aws" {
  alias   = "dr"
  region  = var.dr_region
  profile = "forteca-management"
}
