output "org_id" {
  description = "AWS Organization ID"
  value       = aws_organizations_organization.this.id
}

output "org_root_id" {
  description = "Root OU ID"
  value       = aws_organizations_organization.this.roots[0].id
}

output "ou_ids" {
  description = "Map of OU name => OU ID"
  value       = { for k, v in aws_organizations_organizational_unit.this : k => v.id }
}

output "member_account_ids" {
  description = "Map of account name => account ID"
  value       = { for k, v in aws_organizations_account.this : k => v.id }
}
