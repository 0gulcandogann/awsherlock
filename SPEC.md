# AWSherlock v0.1 Specification

## 1. Product

**AWSherlock** is an open-source AWS security scanner.

It inspects AWS environments using read-only access, evaluates security checks, and generates:

- terminal output
- JSON output
- a standalone HTML security report

AWSherlock is a **CLI security tool**, not a SaaS platform and not a web application.

The v0.1 release is planned for **20 working days / 4 weeks**.

---

## 2. v0.1 Goal

A user must be able to:

```bash
awsherlock scan
awsherlock scan --profile production
awsherlock scan --role arn:aws:iam::123456789012:role/AWSherlockAuditRole
awsherlock scan --services iam,s3
awsherlock scan organization
awsherlock scan snapshot.json
```

and receive security findings through:

```text
Console
JSON
Standalone HTML
```

The HTML report must be self-contained and open locally without a server.

---

## 3. Supported AWS Services

v0.1 targets approximately 30 checks across these services:

1. IAM
2. S3
3. EC2 / Security Groups
4. Lambda
5. Secrets Manager
6. CloudTrail
7. KMS

AWS Organizations is supported for account discovery and multi-account scanning.

---

## 4. Authentication Model

AWSherlock must never implement its own long-lived credential storage.

Supported credential sources:

- default AWS credential chain
- AWS CLI named profiles
- AWS IAM Identity Center / SSO through the AWS SDK credential chain
- existing temporary credentials
- STS AssumeRole

### Single-account flow

```text
Credential Provider
        |
        v
    ScanContext
        |
        v
   AWS Session
        |
        v
    Collectors
```

### Cross-account flow

```text
Source Credentials
        |
        v
   sts:AssumeRole
        |
        v
Temporary Credentials
        |
        v
   Target Account
```

Collectors must not create independent boto3 sessions.

Every collector receives an account/session context from the scanner.

---

## 5. AWS Organizations

Organization scanning must follow this model:

```text
Management / Delegated Administrator Account
                    |
                    v
             AWS Organizations
                    |
              List Accounts
                    |
          +---------+---------+
          |         |         |
          v         v         v
       Account A Account B Account C
          |         |         |
          v         v         v
        AssumeRole into each account
          |
          v
        Run scanner
```

The role name should be configurable.

Default future convention:

```text
AWSherlockAuditRole
```

Organization support in v0.1 includes:

- account discovery
- account metadata
- AssumeRole into target accounts
- per-account scanning
- per-account findings
- account filtering in reports

SCP security analysis is **not** part of v0.1.

---

## 6. Scanner Architecture

The scanner must use a modular pipeline:

```text
Credential Provider
        |
        v
    ScanContext
        |
        v
     Collector
        |
        v
 Normalized Resource
        |
        v
    Rule Engine
        |
        v
      Finding
        |
   +----+----+
   |    |    |
   v    v    v
Console JSON HTML
```

Collectors collect facts.

Rules evaluate facts.

Reporters render findings.

These responsibilities must remain separate.

---

## 7. Finding Model

Every security finding must use a normalized model with at least:

```text
id
title
description
severity
service
account_id
region
resource_id
resource_arn
evidence
risk
remediation
references
```

Recommended severity values:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

Example:

```json
{
  "id": "AWSH-S3-001",
  "title": "S3 bucket allows public access",
  "severity": "HIGH",
  "service": "s3",
  "account_id": "123456789012",
  "region": "eu-central-1",
  "resource_id": "production-backups",
  "resource_arn": "arn:aws:s3:::production-backups",
  "evidence": {
    "BlockPublicAcls": false,
    "BlockPublicPolicy": false
  },
  "risk": "Unauthenticated users may be able to access bucket contents.",
  "remediation": "Enable S3 Block Public Access.",
  "references": []
}
```

---

## 8. Permission Coverage

Permission failures must never silently become PASS results.

AWSherlock should distinguish:

```text
PASS
FAIL
ERROR
NOT_SCANNED
PARTIAL
```

Example report coverage:

```text
IAM          FULL
S3           FULL
EC2          FULL
Lambda       PARTIAL
CloudTrail   ACCESS_DENIED
```

If a collector cannot inspect a resource due to missing permissions, the report must make this visible.

---

## 9. Reporters

### Console

Console output should be concise and useful during scanning.

Example:

```text
AWSherlock v0.1

Account: 123456789012
Region: eu-central-1

Scanning IAM...            OK
Scanning S3...             OK
Scanning EC2...            OK

Resources inspected: 82
Findings: 17

CRITICAL  2
HIGH      5
MEDIUM    7
LOW       3

HTML report:
./awsherlock-report.html
```

### JSON

JSON must preserve structured finding data and scan metadata.

### HTML

The HTML report must:

- be a single standalone file
- require no backend server
- require no internet connection
- embed its CSS and JavaScript
- show scan metadata
- show account metadata
- show finding counts
- show severity distribution
- support text search
- support severity filtering
- support service filtering
- support account filtering
- show evidence
- show remediation
- show permission/coverage status

Preferred implementation:

```text
Jinja2 + vanilla HTML/CSS/JavaScript
```

Do not introduce React, Next.js, Vue, or another frontend framework in v0.1.

---

## 10. Initial Security Checks

The exact implementation order may change, but the v0.1 target is approximately 30 checks.

### S3

- AWSH-S3-001 Public access exposure
- AWSH-S3-002 Default encryption disabled or insufficiently configured
- AWSH-S3-003 Versioning disabled
- AWSH-S3-004 Server access logging disabled
- AWSH-S3-005 Potentially unsafe bucket policy

### IAM

- AWSH-IAM-001 AdministratorAccess attached
- AWSH-IAM-002 Wildcard Action
- AWSH-IAM-003 Wildcard Resource
- AWSH-IAM-004 Console user without MFA
- AWSH-IAM-005 Old access key
- AWSH-IAM-006 Potentially stale credential

### EC2 / Security Groups

- AWSH-EC2-001 SSH exposed to 0.0.0.0/0
- AWSH-EC2-002 RDP exposed to 0.0.0.0/0
- AWSH-EC2-003 Sensitive database port exposed to internet
- AWSH-EC2-004 Instance permits IMDSv1
- AWSH-EC2-005 Public EC2 instance
- AWSH-EC2-006 Unencrypted EBS volume

### Lambda

- AWSH-LAMBDA-001 Public Lambda Function URL
- AWSH-LAMBDA-002 Potentially excessive execution role
- AWSH-LAMBDA-003 Unsupported/deprecated runtime

### Secrets Manager

- AWSH-SECRET-001 Rotation disabled
- AWSH-SECRET-002 Potentially unsafe resource policy
- AWSH-SECRET-003 Encryption configuration issue

### CloudTrail

- AWSH-CT-001 No usable CloudTrail
- AWSH-CT-002 Multi-region/global logging issue
- AWSH-CT-003 Log file validation disabled

### KMS

- AWSH-KMS-001 Key rotation disabled
- AWSH-KMS-002 Potentially permissive key policy

Final check count may vary slightly, but v0.1 must remain intentionally limited.

---

## 11. Snapshot Mode

AWSherlock should eventually support an offline workflow:

```text
AWS
 |
 v
Collector
 |
 v
Snapshot JSON
 |
 v
Rule Engine
 |
 v
Findings
```

Target commands:

```bash
awsherlock snapshot --output awsherlock-snapshot.json
awsherlock scan snapshot.json
```

This is useful for:

- offline analysis
- deterministic testing
- report regeneration
- sharing sanitized scan data
- development without repeated AWS API calls

---

## 12. v0.1 Non-Goals

The following features are explicitly **out of scope** for v0.1:

- SaaS dashboard
- login / user accounts
- backend web server
- database service
- React / Next.js UI
- attack-path engine
- graph visualization
- SCP security analysis
- CloudFormation setup generator
- StackSets deployment
- Security Hub integration
- SARIF
- GitHub Action integration
- CIS benchmark certification/mapping
- PCI/SOC2 compliance mapping
- Bedrock / AgentCore scanner
- AI-generated remediation
- multi-cloud support
- Kubernetes scanning
- continuous monitoring daemon

New ideas belong in `IDEAS.md`.

They do not change this specification during the 20-day v0.1 cycle.

---

## 13. Engineering Principles

1. Read-only by default.
2. Never store AWS credentials.
3. Prefer temporary AWS credentials.
4. No collector-specific boto3 session creation.
5. Separate collection, evaluation, and reporting.
6. Missing permissions must be visible.
7. Every rule requires tests.
8. Avoid false confidence.
9. Avoid unnecessary dependencies.
10. Keep v0.1 small enough to release in 20 working days.

---

## 14. Release Definition of Done

AWSherlock v0.1 is releasable when the following are working:

```text
awsherlock scan
awsherlock scan --profile NAME
awsherlock scan --role ROLE_ARN
awsherlock scan --services iam,s3
awsherlock scan organization
awsherlock scan snapshot.json
```

and the tool can produce:

```text
Console output
JSON output
Standalone HTML output
```

The release should include:

- approximately 7 AWS services
- approximately 30 security checks
- multi-account scanning
- permission coverage reporting
- unit tests
- mocked AWS tests
- packaging
- Docker support
- README
- LICENSE
- CHANGELOG
- GitHub release tag `v0.1.0`

Do not delay v0.1 for v0.2 features.
