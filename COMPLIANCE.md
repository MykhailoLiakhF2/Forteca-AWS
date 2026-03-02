# Forteca-AWS — ISO 27001 Compliance Statement

**Account:** 111111111111 (management) | **Organization:** o-exampleorg  
**Primary Region:** eu-north-1 (Stockholm) | **DR Region:** eu-west-1 (Ireland)  
**Environment:** Lab (production-equivalent architecture, relaxed retention for cost)  
**Last Updated:** 2026-02  

---

## Overview

Forteca-AWS is a Multi-Account AWS Secure Landing Zone implementing security controls aligned with **ISO/IEC 27001:2022** (Information Security Management System).  
The infrastructure is fully defined as code using **Terraform** and deployed across an AWS Organization with three dedicated accounts:

| Account | ID | Purpose |
|---|---|---|
| Management | 111111111111 | Root of the organization, Terraform execution, central logging |
| Security | 222222222222 | Delegated admin for GuardDuty, Security Hub, Config aggregation |
| Workload | 333333333333 | Application workloads, subject to SCPs and backup policies |

---

## RTO / RPO Targets

| Metric | Target | Implementation |
|---|---|---|
| **RPO** (Recovery Point Objective) | **24 hours** | Daily backups at 02:00 UTC. Maximum data loss window = 1 day |
| **RTO** (Recovery Time Objective) | **4 hours** | Cross-region copies in DR vault (eu-west-1). Restore procedure documented below |
| Backup frequency | Daily + Weekly | Daily: 02:00 UTC, 7-day retention. Weekly: Sunday 03:00 UTC, 30-day retention |
| DR copy retention | 14 days | Copies replicated to `forteca-backup-vault-dr` in eu-west-1 |
| Backup coverage | Tag-based | All resources tagged `Backup=true` are automatically enrolled |

### Restore Procedure (high-level)
1. Open AWS Backup console → Backup Vaults → `forteca-backup-vault-dr` (eu-west-1)
2. Select the restore point closest to the target recovery time
3. Choose "Restore" and select target account + region
4. Monitor restore job status; verify resource integrity post-restore
5. Update DNS / routing to point to restored resources
6. Document actual RTO achieved for post-incident review

---

## ISO 27001 Control Mapping

### A.5 — Information Security Policies

| Control | Ref | Implementation | Status |
|---|---|---|---|
| Information security policy | A.5.1 | Security guardrails enforced via Service Control Policies (SCPs) at Organizations level. Cannot be bypassed by any member account. | ✅ |

---

### A.8 — Asset Management

| Control | Ref | Implementation | Status |
|---|---|---|---|
| Inventory of assets | A.8.1 | AWS Config records the complete configuration state of all resources in all accounts via the organization aggregator in the Security account. | ✅ |
| Acceptable use of assets | A.8.1.3 | SCP `deny_region_restriction` restricts all API calls to approved regions (eu-north-1, eu-west-1). Resources cannot be created outside these regions. | ✅ |

---

### A.9 — Access Control

| Control | Ref | Implementation | Status |
|---|---|---|---|
| Access control policy | A.9.1.1 | IAM policies follow least privilege. `terraform_admin` has scoped permissions; no wildcard `*:*` in member accounts. | ✅ |
| Privileged access management | A.9.2.3 | SCP `deny_root_usage` blocks root account API calls across all member accounts. CloudWatch alarm `forteca-root-account-usage` fires on any root activity in management account. | ✅ |
| Secure log-on procedures | A.9.4.2 | MFA enabled on root account and `terraform_admin` IAM user. CloudWatch alarm `forteca-console-login-no-mfa` detects and alerts on console logins without MFA. | ✅ |

---

### A.10 — Cryptography

| Control | Ref | Implementation | Status |
|---|---|---|---|
| Policy on use of cryptographic controls | A.10.1.1 | All data at rest encrypted with AWS KMS: CloudTrail logs, S3 buckets, CloudWatch Log Groups, backup vaults, SNS topics. | ✅ |
| Key management | A.10.1.2 | Customer-managed KMS keys for CloudTrail (`alias/forteca-cloudtrail`) and Backup (`alias/forteca-backup`, `alias/forteca-backup-dr`). Key rotation enabled. Separate keys per region. | ✅ |

---

### A.12 — Operations Security

| Control | Ref | Implementation | Status |
|---|---|---|---|
| Event logging | A.12.4.1 | AWS CloudTrail organization trail `forteca-org-trail` captures all API calls across all accounts and regions. Multi-region, global service events, log file validation enabled. | ✅ |
| Protection of log information | A.12.4.2 | CloudTrail logs written to S3 with bucket policies preventing deletion. SCP `deny_cloudtrail_delete` prevents CloudTrail from being stopped or deleted by any account. CloudWatch alarm `forteca-cloudtrail-changes` detects any modification attempt. | ✅ |
| Administrator and operator logs | A.12.4.3 | CloudWatch Metric Filters on CloudTrail log group detect: root usage, unauthorized API calls, console logins without MFA, CloudTrail modifications. All generate CloudWatch Alarms → SNS email. | ✅ |
| Information backup | A.12.3.1 | AWS Backup plan with daily and weekly schedules. Cross-region copies to eu-west-1 DR vault. Tag-based coverage. CloudWatch alarm `forteca-backup-job-failed` and EventBridge rule provide real-time failure alerting. | ✅ |
| WORM protection (integrity) | A.12.3.1 | Backup Vault Lock available (currently disabled for lab; enable `enable_vault_lock=true` to activate WORM with 3-day grace period). Prevents backup deletion or modification. | ⚠ Lab: disabled |

---

### A.13 — Communications Security

| Control | Ref | Implementation | Status |
|---|---|---|---|
| Network access controls | A.13.1.1 | All API traffic over TLS (enforced by AWS). S3 bucket policies include `aws:SecureTransport` deny for HTTP. | ✅ |

---

### A.16 — Information Security Incident Management

| Control | Ref | Implementation | Status |
|---|---|---|---|
| Reporting information security events | A.16.1.2 | EventBridge rules route GuardDuty HIGH/CRITICAL findings and Security Hub HIGH/CRITICAL findings to SNS `forteca-security-alerts` (security account). Ops-level events (backup failures, Config violations, CloudTrail events) routed to SNS `forteca-ops-alerts` (management account). | ✅ |
| Response to information security incidents | A.16.1.5 | GuardDuty active in management and security accounts. Security Hub aggregates findings from GuardDuty, AWS Foundational Security Best Practices (FSBP), CIS AWS Foundations Benchmark 1.4, and PCI DSS. | ✅ |

---

### A.17 — Business Continuity Management

| Control | Ref | Implementation | Status |
|---|---|---|---|
| Planning information security continuity | A.17.1.1 | DR architecture: cross-region backup copies to eu-west-1. RPO 24h / RTO 4h. Separate KMS keys and vaults in DR region. | ✅ |
| Implementing information security continuity | A.17.1.2 | AWS Backup automatically copies daily jobs to DR vault. Restore procedure documented in this document. | ✅ |
| Verify, review and evaluate continuity | A.17.1.3 | CloudWatch Dashboard `Forteca-Security-DR` provides continuous visibility into backup job success/failure rates. | ✅ |

---

### A.18 — Compliance

| Control | Ref | Implementation | Status |
|---|---|---|---|
| Compliance with legal and contractual requirements | A.18.1.3 | All data stored in EU regions (eu-north-1, eu-west-1) only. SCP `deny_region_restriction` enforces this at the Organizations level — no exceptions possible. | ✅ |
| Review of information security policies | A.18.2.2 | AWS Config evaluates 21 rules continuously across all accounts. Non-compliant evaluations trigger EventBridge → SNS notification. Config aggregator in security account provides organization-wide compliance view. | ✅ |
| Technical compliance review | A.18.2.3 | IAM Access Analyzer `forteca-org-access-analyzer` continuously reviews resource policies for unintended public or cross-account access at organization scope. | ✅ |

---

## Security Services Summary

| Service | Scope | Purpose |
|---|---|---|
| AWS Organizations | Organization | Account isolation, SCP enforcement |
| Service Control Policies | Organization | Deny region restrictions, protect CloudTrail, deny root usage |
| AWS CloudTrail | Organization trail | Immutable audit log of all API calls |
| AWS GuardDuty | Management + Security accounts | ML-based threat detection |
| AWS Security Hub | Security account (delegated admin) | Centralized findings: FSBP, CIS 1.4, PCI DSS |
| AWS Config | Management account | Resource configuration recording, 21 compliance rules |
| Config Aggregator | Security account | Organization-wide compliance view |
| IAM Access Analyzer | Management account | Resource policy analysis (organization scope) |
| AWS Backup | Management account | Automated backups with cross-region DR copies |
| AWS KMS | Management + DR regions | Encryption key management |
| CloudWatch Alarms | Management account | Automated alerting on security events |
| EventBridge | Management account | Real-time event routing (backup failures, compliance) |
| CloudWatch Dashboard | Management account | Single pane of glass for Security & DR |

---

## Deviations from Production Best Practice (Lab Environment)

The following controls are intentionally relaxed for cost and operational convenience in this lab environment. Each deviation is flagged in Terraform with a comment and variable.

| Item | Lab Setting | Production Setting | Terraform Variable |
|---|---|---|---|
| Backup Vault Lock (WORM) | Disabled | Enabled (3-day grace, then permanent) | `enable_vault_lock = true` |
| Daily backup retention | 7 days | 30+ days | `daily_retention_days` |
| Weekly backup retention | 30 days | 365 days | `weekly_retention_days` |
| DR copy retention | 14 days | 90+ days | `dr_copy_retention_days` |
| S3 force_destroy | true | false | Hardcoded, change before prod |
| prevent_destroy lifecycle | false | true | Hardcoded in modules |

---

## Architecture Diagram (text)

```
┌─────────────────────────────────────────────────────────────────┐
│                    AWS Organization o-exampleorg                │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Root (r-4cxy)  — SCPs: deny_region, deny_cloudtrail,     │   │
│  │                        deny_root                         │   │
│  └──────────────┬─────────────────────┬─────────────────────┘   │
│                 │                     │                         │
│         ┌──────▼──────┐       ┌───────▼──────┐                  │
│         │ Security OU │       │ Workload OU  │                  │
│         │             │       │              │                  │
│         │ ┌─────────┐ │       │ ┌──────────┐ │                  │
│         │ │Security │ │       │ │Workload  │ │                  │
│         │ │Account  │ │       │ │Account   │ │                  │
│         │ │222222.. │ │       │ │333333..  │ │                  │
│         │ └─────────┘ │       │ └──────────┘ │                  │
│         └─────────────┘       └──────────────┘                  │
│                                                                 │
│  Management Account (111111111111)                              │
│  ├── CloudTrail org trail → S3 + CloudWatch Logs                │
│  ├── GuardDuty (member) → delegated to Security account         │
│  ├── AWS Backup → eu-north-1 vault + eu-west-1 DR vault         │
│  ├── CloudWatch Alarms (5) + EventBridge Rules (2)              │
│  └── CloudWatch Dashboard: Forteca-Security-DR                  │
│                                                                 │
│  Security Account (222222222222) — delegated admin              │
│  ├── GuardDuty (admin) → findings → S3 + EventBridge → SNS      │
│  ├── Security Hub (admin) → FSBP + CIS 1.4 + PCI DSS            │
│  ├── Config Aggregator → org-wide compliance view               │
│  └── IAM Access Analyzer (organization scope)                   │
└─────────────────────────────────────────────────────────────────┘

DR Region: eu-west-1 (Ireland)
└── Backup Vault: forteca-backup-vault-dr
    └── Daily cross-region copies, 14-day retention
```

---

*This document is generated from the Terraform codebase and reflects the actual deployed state.*  
*For any discrepancy, the Terraform state file is the authoritative source of truth.*
