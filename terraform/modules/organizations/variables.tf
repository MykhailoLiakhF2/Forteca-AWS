variable "aws_region" {
  description = "Primary AWS region"
  type        = string
  default     = "eu-west-1"
}

variable "project_name" {
  description = "Project name prefix used in all resource names (e.g. 'forteca')"
  type        = string
  default     = "forteca"
}

variable "org_units" {
  description = "Map of OU name => parent (only 'root' supported for now)"
  type        = map(string)
  default = {
    Security = "root"
    Workload = "root"
  }
}

variable "member_accounts" {
  description = "Member accounts to create inside the org"
  type = map(object({
    email = string
    ou    = string
  }))
}

variable "tags" {
  description = "Common resource tags"
  type        = map(string)
  default     = {}
}
