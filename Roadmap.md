# AWSherlock — v0.1 Development Roadmap

AWSherlock v0.1 will be developed over **20 focused working days / 4 weeks**.

This roadmap is intentionally linear.

Do not skip ahead.

Do not implement future days early.

Do not combine multiple days unless the project owner explicitly asks you to.

---

# Critical Progression Rule

You must work on **one day at a time**.

After completing the current day's task:

1. Run the required tests.
2. Verify every acceptance criterion for that day.
3. Summarize the work.
4. Stop.
5. Ask the project owner for permission to continue.

Use this exact final question:

```text
Day X is complete.

Would you like me to continue with Day X+1?
```

Do not begin the next day until the user explicitly approves.

Examples of approval:

```text
yes
continue
go to day 2
start next day
devam
geç
```

Without explicit approval, stop working.

---

# Day 1 — Project Bootstrap and CLI

## Goal

Create the first working AWSherlock CLI.

No AWS integration yet.

## Implement

Create the Python package structure:

```text
src/
└── awsherlock/
    ├── __init__.py
    ├── __main__.py
    └── cli.py
```

Use:

```text
Python 3.11+
Typer
Rich
pytest
```

Implement:

```bash
awsherlock --help
awsherlock --version
awsherlock scan --help
```

Initial version:

```text
0.1.0-dev
```

The `scan` command may be a placeholder.

## Tests

Test:

```text
--help
--version
scan --help
```

No AWS credentials should be required.

## Done when

```text
[ ] package installs locally
[ ] awsherlock --help works
[ ] awsherlock --version works
[ ] awsherlock scan --help works
[ ] CLI tests pass
[ ] no AWS API call occurs
```

---

# Day 2 — AWS Session and Scan Context

## Goal

Introduce the AWS session abstraction without implementing real security scans.

## Implement

Add a centralized AWS session layer.

Suggested structure:

```text
src/awsherlock/aws/
├── __init__.py
├── session.py
└── context.py
```

Implement support for:

```bash
awsherlock scan
awsherlock scan --profile production
```

The session layer must use the standard boto3 credential chain.

Create a `ScanContext` containing useful metadata such as:

```text
account_id
caller_arn
partition
profile
region
session
```

Use STS `GetCallerIdentity` to identify the current account.

Collectors must never create their own boto3 sessions.

## Tests

Mock AWS calls.

Test:

```text
default credential session
named profile
ScanContext creation
GetCallerIdentity parsing
credential errors
```

## Done when

```text
[ ] default AWS session works
[ ] named profile path works
[ ] ScanContext exists
[ ] account ID can be resolved
[ ] no credential is persisted
[ ] tests pass
```

---

# Day 3 — STS AssumeRole

## Goal

Support cross-account scanning through temporary credentials.

## Implement

Support:

```bash
awsherlock scan \
  --role arn:aws:iam::123456789012:role/AWSherlockAuditRole
```

Add AssumeRole handling to the session layer.

Support optional configuration for:

```text
role session name
external ID if provided
source profile/session
```

Do not store temporary credentials.

Do not log:

```text
AccessKeyId
SecretAccessKey
SessionToken
```

The resulting session should produce a normal `ScanContext`.

## Security review

Review:

```text
credential leakage
trust assumptions
temporary credential handling
error messages
role ARN validation
AccessDenied behavior
```

## Tests

Mock:

```text
successful AssumeRole
AccessDenied
invalid role ARN
expired/failed source credential
temporary credential construction
```

## Done when

```text
[ ] --role works
[ ] temporary session is used
[ ] no credentials are logged
[ ] AccessDenied is visible
[ ] tests pass
```

---

# Day 4 — Core Models and Rule Engine

## Goal

Create the normalized internal data model.

## Implement

Add models for:

```text
ScanMetadata
Resource
Finding
CoverageStatus
Severity
```

Suggested finding data:

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

Create a simple rule-engine contract.

Concept:

```text
Resource
   |
   v
Rule.evaluate()
   |
   v
Finding[]
```

Rules must not print output directly.

## Tests

Test:

```text
model validation
severity values
finding serialization
basic rule execution
empty result behavior
```

## Done when

```text
[ ] normalized models exist
[ ] finding model exists
[ ] rule contract exists
[ ] rules are independent from reporters
[ ] tests pass
```

---

# Day 5 — First Real AWS Scan: S3 Foundation

## Goal

Produce the first real AWSherlock security finding.

## Implement

Create an S3 collector.

Collect at minimum:

```text
bucket name
bucket ARN
bucket region
public access block configuration
```

Implement:

```text
AWSH-S3-001
Public access exposure
```

The command:

```bash
awsherlock scan --services s3
```

should be able to produce a real finding.

Handle:

```text
AccessDenied
NoSuchPublicAccessBlockConfiguration
regional bucket behavior
```

## Tests

Fixtures:

```text
secure bucket
public bucket
partial configuration
AccessDenied
multiple buckets
```

## Done when

```text
[ ] S3 collector works
[ ] AWSH-S3-001 works
[ ] finding appears in CLI
[ ] AccessDenied is not PASS
[ ] tests pass
```

---

# Day 6 — Complete S3 Scanner

## Goal

Build the initial S3 security module.

## Implement

Add checks approximately covering:

```text
AWSH-S3-001 Public access exposure
AWSH-S3-002 Encryption configuration
AWSH-S3-003 Versioning disabled
AWSH-S3-004 Access logging disabled
AWSH-S3-005 Potentially unsafe bucket policy
```

Reuse one normalized S3 resource model where practical.

Avoid repeated API calls when the same collected fact can support multiple rules.

## Tests

Each rule must have at least:

```text
insecure fixture -> finding
secure fixture -> no finding
```

Also test:

```text
AccessDenied
missing configuration
multiple buckets
```

## Done when

```text
[ ] approximately 5 S3 checks work
[ ] duplicate AWS calls are minimized
[ ] tests cover each rule
[ ] tests pass
```

---

# Day 7 — IAM Scanner

## Goal

Add core IAM security checks.

## Implement

Create IAM collectors and rules for approximately:

```text
AWSH-IAM-001 AdministratorAccess attached
AWSH-IAM-002 Wildcard Action
AWSH-IAM-003 Wildcard Resource
AWSH-IAM-004 Console user without MFA
AWSH-IAM-005 Old access key
AWSH-IAM-006 Potentially stale credential
```

Correctly handle:

```text
managed policies
inline policies
policy versions
users
roles where relevant
access key metadata
pagination
```

Do not overclaim policy risk without evidence.

## Security review

Focus on:

```text
policy document parsing
wildcard semantics
false positives
false negatives
pagination
global IAM behavior
```

## Done when

```text
[ ] IAM resources are collected
[ ] approximately 6 IAM checks work
[ ] policy pagination/version handling works
[ ] tests pass
```

---

# Day 8 — EC2 and Security Groups

## Goal

Detect common network and instance exposure issues.

## Implement

Create checks approximately covering:

```text
AWSH-EC2-001 SSH exposed to 0.0.0.0/0
AWSH-EC2-002 RDP exposed to 0.0.0.0/0
AWSH-EC2-003 Sensitive database port exposed to internet
AWSH-EC2-004 IMDSv1 permitted
AWSH-EC2-005 Public EC2 instance
AWSH-EC2-006 Unencrypted EBS volume
```

Consider both:

```text
0.0.0.0/0
::/0
```

Security group rules may use:

```text
single ports
port ranges
protocol -1
```

Handle all correctly.

## Tests

Include edge cases for port ranges and IPv6.

## Done when

```text
[ ] EC2 collector works
[ ] security group evaluation works
[ ] IMDS configuration is evaluated
[ ] EBS encryption is evaluated
[ ] tests pass
```

---

# Day 9 — Lambda and Secrets Manager

## Goal

Add serverless and secret-storage security checks.

## Lambda

Implement approximately:

```text
AWSH-LAMBDA-001 Public Lambda Function URL
AWSH-LAMBDA-002 Potentially excessive execution role
AWSH-LAMBDA-003 Unsupported/deprecated runtime
```

Do not retrieve or log environment variable values unless explicitly required.

Prefer environment variable names only if needed.

## Secrets Manager

Implement approximately:

```text
AWSH-SECRET-001 Rotation disabled
AWSH-SECRET-002 Potentially unsafe resource policy
AWSH-SECRET-003 Encryption configuration issue
```

Never retrieve secret values.

## Tests

Explicitly ensure secret values are never requested.

## Done when

```text
[ ] Lambda scanner works
[ ] Secrets Manager scanner works
[ ] no secret value API is used
[ ] tests pass
```

---

# Day 10 — CloudTrail and KMS

## Goal

Complete the initial set of AWS service scanners.

## CloudTrail

Implement approximately:

```text
AWSH-CT-001 No usable CloudTrail
AWSH-CT-002 Multi-region/global logging issue
AWSH-CT-003 Log file validation disabled
```

Carefully account for:

```text
multi-region trails
organization trails
regional behavior
```

## KMS

Implement approximately:

```text
AWSH-KMS-001 Key rotation disabled
AWSH-KMS-002 Potentially permissive key policy
```

Do not automatically classify every wildcard in a KMS policy as vulnerable without considering context.

## Done when

```text
[ ] CloudTrail scanner works
[ ] KMS scanner works
[ ] approximately 25-30 checks now exist overall
[ ] tests pass
```

---

# Day 11 — Snapshot Architecture

## Goal

Separate AWS collection from security evaluation.

## Implement

Create a normalized snapshot format.

Concept:

```text
AWS
 |
 v
Collectors
 |
 v
Snapshot
 |
 v
Rules
 |
 v
Findings
```

Add a command such as:

```bash
awsherlock snapshot --output awsherlock-snapshot.json
```

Snapshot files must not contain:

```text
AWS credentials
session tokens
secret values
private keys
sensitive Lambda environment variable values
```

Define a snapshot schema version.

Example:

```text
schema_version: 1
```

## Tests

Test:

```text
serialization
deserialization
schema version
no credential leakage
```

## Done when

```text
[ ] snapshot file can be created
[ ] normalized resource data is preserved
[ ] secrets/credentials are excluded
[ ] tests pass
```

---

# Day 12 — Offline Scan and JSON Reporter

## Goal

Scan previously collected data and produce machine-readable output.

## Implement

Support:

```bash
awsherlock scan snapshot.json
```

The same rule engine should evaluate live and offline resources.

Add JSON output:

```bash
awsherlock scan --output json
```

or equivalent CLI design consistent with the project.

JSON should contain:

```text
scan metadata
coverage
findings
summary
```

## Done when

```text
[ ] snapshot can be scanned offline
[ ] live/offline rule logic is shared
[ ] JSON output works
[ ] tests pass
```

---

# Day 13 — Standalone HTML Reporter v1

## Goal

Generate the first standalone HTML security report.

## Implement

Use:

```text
Jinja2
vanilla HTML
vanilla CSS
vanilla JavaScript
```

No external CDN.

No web server.

No frontend framework.

Generate:

```text
awsherlock-report.html
```

Display:

```text
AWSherlock branding
scan date/time
account information
resource count
finding count
severity summary
finding list
finding details
evidence
remediation
```

The report must work when opened directly with:

```text
file://
```

## Done when

```text
[ ] standalone HTML is generated
[ ] no internet connection is required
[ ] no external JS/CSS is loaded
[ ] findings render correctly
[ ] tests pass
```

---

# Day 14 — HTML Reporter v2

## Goal

Make the report useful for real assessment work.

## Implement

Add:

```text
text search
severity filter
service filter
finding ID filtering if useful
sortable finding presentation
coverage section
account metadata
clear empty states
```

Do not convert the project to a web application.

All JavaScript must remain embedded/local.

## Optional if simple

Add lightweight charts using plain HTML/CSS/JS only.

Do not add a large charting dependency unless explicitly approved.

## Done when

```text
[ ] search works
[ ] severity filter works
[ ] service filter works
[ ] coverage is visible
[ ] report remains standalone
[ ] tests pass
```

---

# Day 15 — AWS Organizations and Multi-Account Scan

## Goal

Support organization-wide AWS assessments.

## Implement

Add:

```bash
awsherlock scan organization
```

Support account discovery through AWS Organizations.

Collect metadata such as:

```text
account ID
account name
account status/state
organizational unit when practical
```

Support AssumeRole into each account using a configurable role name.

Example:

```text
AWSherlockAuditRole
```

Flow:

```text
Source Account
     |
     v
Organizations
     |
     v
List Accounts
     |
     v
Target Account
     |
     v
AssumeRole
     |
     v
Scan Account
```

Do not implement SCP security analysis.

## Error handling

One inaccessible account must not necessarily terminate all organization scanning.

Record failures visibly.

## Done when

```text
[ ] accounts can be discovered
[ ] target roles can be assumed
[ ] multiple accounts can be scanned
[ ] failed accounts are reported
[ ] tests pass
```

---

# Day 16 — Permission Coverage and Partial Scans

## Goal

Make scan completeness explicit.

## Implement

Introduce consistent coverage states.

Example:

```text
IAM           FULL
S3            FULL
EC2           FULL
Lambda        PARTIAL
CloudTrail    ACCESS_DENIED
KMS           NOT_SCANNED
```

Coverage should be available in:

```text
console
JSON
HTML
```

A permission failure must never silently become a secure result.

Track coverage at useful granularity.

Potentially:

```text
account
service
collector
```

Avoid unnecessary complexity.

## Done when

```text
[ ] AccessDenied is consistently represented
[ ] partial collection is represented
[ ] console shows coverage problems
[ ] JSON shows coverage
[ ] HTML shows coverage
[ ] tests pass
```

---

# Day 17 — Test and Security Hardening Day

## Goal

Improve reliability instead of adding features.

No new scanner features today.

## Work

Audit existing test coverage.

Add missing tests for:

```text
pagination
AccessDenied
partial responses
missing fields
empty accounts
multi-region behavior
global services
role assumption failure
organization account failure
snapshot compatibility
HTML escaping
JSON serialization
CLI errors
```

Perform a security review for:

```text
credential leakage
secret leakage
unsafe logs
HTML injection
untrusted AWS metadata
policy parsing
exception handling
```

Fix issues discovered during this review.

Do not perform unrelated refactors.

## Done when

```text
[ ] important edge cases are tested
[ ] security review completed
[ ] high-impact issues fixed
[ ] full test suite passes
```

---

# Day 18 — Packaging, Installation, and Docker

## Goal

Make AWSherlock easy to install and run.

## Implement

Ensure Python packaging works cleanly.

Test:

```bash
pip install .
```

or development equivalent.

Prepare for:

```bash
pipx install ...
```

Add Docker support.

Docker must not embed AWS credentials.

Credentials should be supplied at runtime through supported AWS mechanisms.

Add or verify:

```text
Dockerfile
.dockerignore
package metadata
version handling
```

## Done when

```text
[ ] local package install works
[ ] awsherlock entry point works after installation
[ ] Docker image builds
[ ] Docker CLI launches
[ ] no credentials are baked into image
[ ] tests pass
```

---

# Day 19 — Documentation and Demo Experience

## Goal

Prepare the repository for public users.

## README

Create a polished README containing:

```text
project description
features
installation
quick start
authentication methods
named profile example
AssumeRole example
organization example
service filtering
snapshot usage
HTML report usage
security model
permission requirements
architecture
supported checks
known limitations
development instructions
contribution guidance
```

Do not claim unsupported capabilities.

## Demo

Create sanitized example data if useful.

Potentially include:

```text
example snapshot
example JSON result
example HTML report
screenshots
```

Ensure no real account IDs, credentials, secrets, or private organization information are exposed.

## Done when

```text
[ ] README reflects real behavior
[ ] quick-start commands were tested
[ ] examples are sanitized
[ ] public repository experience is understandable
```

---

# Day 20 — v0.1 Release Candidate

## Goal

Release AWSherlock v0.1.0.

No new features today.

## Final Review

Verify:

```text
awsherlock --help
awsherlock --version

awsherlock scan
awsherlock scan --profile NAME
awsherlock scan --role ROLE_ARN
awsherlock scan --services iam,s3
awsherlock scan organization
awsherlock scan snapshot.json
```

Verify outputs:

```text
Console
JSON
Standalone HTML
```

Run:

```text
full unit test suite
linting if configured
package build
fresh package installation
Docker build
CLI smoke test
HTML report smoke test
snapshot scan
```

Review repository for accidental:

```text
credentials
account IDs
secret values
debug output
temporary files
generated reports
test artifacts
```

Prepare:

```text
CHANGELOG
release notes
v0.1.0 version
Git tag
```

## v0.1 Definition of Done

Target:

```text
approximately 7 AWS services
approximately 30 checks
AWS profiles
STS AssumeRole
AWS Organizations
multi-account scanning
snapshot scanning
permission coverage
console output
JSON output
standalone HTML report
tests
Docker
documentation
```

Do not delay v0.1 for features that belong to v0.2.

## Done when

```text
[ ] full test suite passes
[ ] package builds
[ ] clean installation works
[ ] Docker works
[ ] HTML report works
[ ] README matches product
[ ] no secrets exist in repository
[ ] CHANGELOG exists
[ ] version is v0.1.0
[ ] release candidate is ready
```

After completion:

```text
Day 20 is complete.

AWSherlock v0.1.0 is ready for release.
```

Do not begin v0.2 automatically.

---

# Future v0.2 Ideas

These are not part of this roadmap.

```text
Attack-path detection
SCP analysis
OU security analysis
CloudFormation setup generator
StackSets helper
Security Hub integration
SARIF output
GitHub Action
CIS mapping
PCI DSS mapping
SOC 2 mapping
Bedrock / AgentCore checks
graph visualization
scan diffing
suppression rules
policy-as-code
AI-assisted remediation
```

Keep these out of v0.1 unless the project owner explicitly changes the scope.

---

# Codex Final Rule

At the end of every day except Day 20, stop and ask:

```text
Day X is complete.

Would you like me to continue with Day X+1?
```

Do not make any code changes for the next day until the project owner explicitly approves.
