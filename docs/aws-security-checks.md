# AWS Security Checks

CloudProwler currently performs the following security assessments.

## IAM AdministratorAccess

Detects IAM users or roles with the AdministratorAccess managed policy.

Risk:
High

---

## IAM Privilege Escalation

Identifies IAM configurations that may allow privilege escalation.

Risk:
Critical

---

## S3 Public Access

Checks whether S3 buckets expose public access.

Risk:
High

---

## EC2 IMDSv1

Detects EC2 instances still using Instance Metadata Service Version 1.

Risk:
Medium

---

## Security Groups

Identifies overly permissive inbound rules.

Examples:

- 0.0.0.0/0
- Open SSH
- Open RDP

Risk:
High