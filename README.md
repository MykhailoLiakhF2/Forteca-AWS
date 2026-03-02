# Forteca-AWS: Multi-Account AWS Secure Landing Zone

![Terraform](https://img.shields.io/badge/Terraform-1.6%2B-7B42BC?logo=terraform) ![AWS Provider](https://img.shields.io/badge/AWS%20Provider-~%3E5.0-FF9900?logo=amazonaws) ![ISO 27001](https://img.shields.io/badge/ISO_27001-Aligned-0070C0) ![License](https://img.shields.io/badge/License-MIT-green)

Forteca-AWS is a secure, multi-account AWS Landing Zone designed to meet **ISO 27001** compliance requirements. It uses Terraform to provision and manage a centralized security operations center, complete with automated backups, organizational structure, compliance auditing, and continuous real-time monitoring.

## Architecture 

The multi-account architecture isolates environments to reduce blast radius and provide separation of duties, a core tenet of ISO 27001.

```mermaid
graph TB
    subgraph ORG["🏢 AWS Organization"]
        direction TB

        subgraph MGMT["📋 Management Account"]
            direction LR
            ORGS["AWS Organizations\n+ SCPs"]
            CT["CloudTrail\nOrg Trail"]
            CFG["AWS Config\nRecorder"]
            BKP["AWS Backup\neu-north-1"]
            CW["CloudWatch\nAlarms + Dashboard"]
        end

        subgraph SEC["🔐 Security Account — Delegated Admin"]
            direction LR
            GD["GuardDuty\nAdmin"]
            SH["Security Hub\nFSBP · CIS · PCI"]
            CFGAGG["Config\nAggregator"]
            SNS_SEC["SNS\nsecurity-alerts"]
            SNS_OPS["SNS\nops-alerts"]
            EB["EventBridge"]
        end

        subgraph WORK["⚙️ Workload Account(s)"]
            TAGGED["Tagged Resources\nEC2 · RDS · EFS"]
        end
    end

    subgraph DR["🌍 DR Region — eu-west-1"]
        BKP_DR["AWS Backup\neu-west-1"]
    end

    ORGS -->|"SCP enforcement"| SEC
    ORGS -->|"SCP enforcement"| WORK

    CT -->|"Org API logs → S3"| SEC
    CFG -->|"Config snapshots"| CFGAGG
    BKP -->|"Cross-region copy"| BKP_DR
    TAGGED -->|"tag: Backup=true"| BKP

    GD -->|"Findings"| SH
    SH -->|"HIGH / CRITICAL"| EB
    EB -->|"Alert"| SNS_SEC
    CW -->|"Threshold breach"| SNS_OPS

    classDef acct fill:#1a1f2e,stroke:#4a9eff,color:#fff,rx:8
    classDef service fill:#0d2137,stroke:#4a9eff,color:#cde,rx:4
    classDef dr fill:#1f2a1a,stroke:#4CAF50,color:#fff,rx:8
    class MGMT,SEC,WORK acct
    class BKP_DR,DR dr
```

## Features

- **Multi-Account Strategy**: Leverages AWS Organizations to manage `Management`, `Security`, and `Workload` accounts.
- **Continuous Compliance (AWS Config)**: Implements ISO 27001 managed rules across all accounts (S3 encryption, IAM MFA enforcement, root account monitoring).
- **Threat Detection (Amazon GuardDuty)**: Intelligent threat detection delegated to the Security account.
- **Security Posture Management (AWS Security Hub)**: Centralized view of security alerts automatically routed to SNS/Email via EventBridge.
- **Immutable Audit Trail (CloudTrail)**: Organization trail with file integrity validation (ISO 27001) stored in a restricted S3 bucket.
- **Resilient Automation (AWS Backup)**: Policies enforce regular backups with cross-region replication and Vault Lock (WORM) ensuring immutability against accidental deletion or ransomware.
- **Real-Time Operational Alarms**: CloudWatch metrics trigger notifications for high-priority events (e.g., Root account login, failed backups, trail modifications).

## Prerequisites

1. An AWS Management account.
2. An AWS IAM User or Role with `AdministratorAccess` in the Management account.
3. [Terraform CLI](https://developer.hashicorp.com/terraform/install) **~> 1.6** installed.
4. AWS CLI configured with credentials for the Management account.

## Deployment Instructions

1. **Clone the repository:**
   ```bash
   git clone <repository_url>
   cd aws-sab/terraform
   ```

2. **Setup the Configuration:**
   Copy the example variables file and adjust the values:
   ```bash
   cp envs/management/terraform.tfvars.example envs/management/terraform.tfvars
   ```
   Open `terraform.tfvars` and edit the configurations, specifically:
   - `aws_account_id` and `security_account_id`
   - `alert_email` and `ops_alert_email`
   - `member_accounts` mapping block

3. **Initialize Terraform:**
   ```bash
   cd envs/management
   terraform init
   ```

4. **Review the Execution Plan:**
   ```bash
   terraform plan
   ```

5. **Apply the Changes:**
   ```bash
   terraform apply
   ```

6. **Confirm SNS Subscriptions:**
   Check the inboxes of both `alert_email` and `ops_alert_email` to confirm the AWS SNS topic subscriptions. Alerts will not be delivered until they are confirmed.

## Project Customization

By changing the `project_name` variable in `terraform.tfvars`, all spawned resources (S3 buckets, KMS aliases, backup vaults, etc.) will dynamically adapt prefixes to seamlessly provision new isolated environments.

## Modules Overview

- **organizations**: Bootstraps the AWS organization, organizational units (OUs), and provisions member accounts.
- **cloudtrail**: Creates org-wide continuous auditing trails delivered to secured S3 buckets.
- **security**: Implements Config Rules, GuardDuty, and Security Hub integrations and delegates administrative tasks to the Security account.
- **backup**: Defines automated backup schedules, cross-region replication for disaster recovery, and sets up immutable vault locks.
- **alerting**: Sets up notifications (SNS), CloudWatch metrics/alarms, and unified dashboards.

## Compliance

For a detailed mapping of AWS controls to ISO/IEC 27001:2022 clauses, see [COMPLIANCE.md](./COMPLIANCE.md).

## License

This project is licensed under the **MIT License** — see [LICENSE](./LICENSE) for full details.
