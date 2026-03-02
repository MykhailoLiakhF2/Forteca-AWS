variable "aws_region" {
  description = "AWS region where bootstrap resources will be created"
  type        = string
  default     = "eu-north-1"
}

variable "state_bucket_name" {
  description = "Name of the S3 bucket for Terraform remote state"
  type        = string
  default     = "forteca-tfstate-mgmt"
}

variable "lock_table_name" {
  description = "Name of the DynamoDB table for state locking"
  type        = string
  default     = "forteca-tfstate-lock"
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Project     = "Forteca-AWS"
    ManagedBy   = "Terraform"
    Environment = "bootstrap"
  }
}
