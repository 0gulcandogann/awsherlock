<div align="center">

# AWSherlock

**Inspect AWS configuration. Understand the risk. Know what was actually scanned.**

Read-only AWS security scanning with offline snapshots and standalone HTML reports.

**7 services · 28 checks · Multi-account scanning · Python 3.11+ · MIT**

[Get started](#installation) · [Try the demo](#try-it-without-an-aws-account) · [Security checks](docs/checks.md) · [Report an issue](https://github.com/0gulcandogann/awsherlock/issues)

</div>

---

AWSherlock is a CLI for reviewing AWS security configuration. Scan an account or an organization, inspect the evidence behind each finding, and share a report that opens directly in a browser.

Missing permissions stay visible. An empty findings list never hides a failed scan.

```bash
awsherlock scan --profile production --services iam,s3 --output html
```

Open `awsherlock-report.html` locally. No server, account signup, or internet connection is needed to view the report.

## What you get

| Capability | Details |
| --- | --- |
| Configuration checks | 28 checks across IAM, S3, EC2, Lambda, Secrets Manager, CloudTrail and KMS |
| Existing AWS authentication | SDK credential chain, named profiles, SSO sessions and STS AssumeRole |
| Organization scanning | Account discovery, configurable audit roles and visible per-account failures |
| Offline analysis | Capture facts once, then evaluate or regenerate reports without AWS access |
| Three output formats | Terminal findings, structured JSON and a single standalone HTML file |
| Interactive reports | Search, severity/service/account filters, sorting, evidence and remediation |
| Explicit coverage | Per-account and per-service visibility into successful, partial and failed collection |

## Installation

Requires **Python 3.11 or newer**. Install from the repository:

```bash
git clone https://github.com/0gulcandogann/awsherlock.git
cd awsherlock
python -m venv .venv
```

Activate your environment:

```bash
# macOS / Linux
source .venv/bin/activate
```

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

Then install and verify:

```bash
python -m pip install .
awsherlock --version
awsherlock scan --help
```

Alternatively, run `pipx install .` from the checkout for an isolated CLI installation. You can also use `python -m awsherlock` in place of `awsherlock`.

## Try it without an AWS account

The repository includes a completely synthetic example with four findings and an intentional permission failure:

```bash
awsherlock scan examples/demo-snapshot.json
awsherlock scan examples/demo-snapshot.json --output json
awsherlock scan examples/demo-snapshot.json --output html --report-file demo.html
```

Open `demo.html` to explore search, filters, evidence and coverage. These commands return **exit code 1** because the example deliberately contains incomplete coverage; the report is still generated.

Explore the [snapshot](examples/demo-snapshot.json) and [JSON report](examples/demo-report.json), or download [the HTML report](https://raw.githubusercontent.com/0gulcandogann/awsherlock/main/examples/demo-report.html) and open it locally. All example identifiers are invented.

## Scan your AWS environment

Configure credentials and a region with your existing AWS CLI/SDK setup. For SSO, sign in first using your normal AWS CLI login. AWSherlock uses the SDK credential chain and does not implement credential storage.

```bash
# All seven services using the default credential chain
awsherlock scan

# A named profile and selected services
awsherlock scan --profile production --services iam,s3

# Assume a role in a target account
awsherlock scan --profile production --role arn:aws:iam::123456789012:role/AWSherlockAuditRole
```

Regional services use the SDK-configured region (`AWS_DEFAULT_REGION` or your profile region). IAM is global; S3 buckets are inspected in their own regions.

### AssumeRole options

```bash
awsherlock scan --profile production --role arn:aws:iam::123456789012:role/AWSherlockAuditRole --role-session-name audit-session --external-id example-external-id
```

The source principal needs `sts:AssumeRole`, and the target role must trust it. Temporary credentials remain in memory. Explicit assumed-role sessions do not automatically refresh; rerun the scan after credentials expire. Interactive MFA parameters are not supported; use an already authenticated source session.

### Scan an organization

```bash
awsherlock scan organization --profile management --services iam,s3 --output html
awsherlock scan organization --profile management --role-name audit/Reader --output json
```

The management or delegated administrator account needs `organizations:ListAccounts`. AWSherlock discovers accounts, reads their `State`, and sequentially assumes `AWSherlockAuditRole` in each active account. Override the target role name or path with `--role-name`.

Each target role needs the relevant service read permissions and a trust policy allowing the source. Inaccessible accounts are reported; remaining accounts continue. Non-active accounts are marked `NOT_SCANNED`.

For organization scans, `--external-id` and `--role-session-name` apply to target roles. `--role` optionally assumes a source discovery role first.

## Reports and snapshots

### HTML

```bash
awsherlock scan --services iam,s3 --output html --report-file report.html
```

Reports include scan metadata, severity counts, evidence, risk, remediation and collection issues. Search includes finding IDs, resources and evidence. Combine severity, service and account filters, or sort by severity, service, resource or finding ID. With JavaScript disabled, all findings remain readable.

CSS and JavaScript are embedded. No CDN, server or external asset is required.

### JSON

```bash
# Structured JSON on stdout
awsherlock scan --services iam,s3 --output json

# Save a report
awsherlock scan --services iam,s3 --output json --report-file findings.json
```

JSON preserves metadata, normalized findings, coverage, collection issues and summary counts. Existing report and snapshot files are never overwritten.

### Capture now, analyze offline

```bash
awsherlock snapshot --profile production --services iam,s3 --output snapshot.json
awsherlock scan snapshot.json
awsherlock scan snapshot.json --output html --report-file offline.html
```

Capture collects facts without evaluating rules. Offline scans use the same rules as live scans and never create an AWS session. Authentication flags are rejected offline; `--services` can select services present in the snapshot.

Snapshots reflect collection time. They contain resource names, account IDs and security metadata; sanitize them before sharing.

## Supported checks

| Service | Checks | What is inspected |
| --- | ---: | --- |
| IAM | 6 | AdministratorAccess, broad policy actions/resources, console MFA, old and unused active keys |
| S3 | 5 | Public access safeguards, encryption configuration, versioning, access logging, public policy status |
| EC2 | 6 | Internet-wide SSH/RDP/database ingress, IMDSv1, public addresses, EBS encryption |
| Lambda | 3 | Public function URLs, broad managed execution-role policies, deprecated runtimes |
| Secrets Manager | 3 | Rotation, broad resource-policy principals, custom encryption key state |
| CloudTrail | 3 | Usable trail, multi-region/global logging, log validation |
| KMS | 2 | Eligible key rotation and broad key-policy principals |

See **[security checks and permissions](docs/checks.md)** for required AWS read permissions, detection details and service-specific limitations. AWSherlock does not create audit roles or modify policies.

## Understand scan coverage

| Status | Meaning |
| --- | --- |
| `COMPLETE` | Applicable known checks were evaluated; this does not mean the account is secure |
| `PARTIAL` | Some checks ran, but facts or permissions were missing |
| `ACCESS_DENIED` | Permission denial prevented evaluation for this entry |
| `ERROR` | Collection or evaluation failed |
| `NOT_SCANNED` | Required facts were missing or an account was not active |

Coverage appears in every report format. Missing-check counts cover known resources; a failed listing can hide an unknown number of resources.

| Exit code | Meaning |
| --- | --- |
| `0` | Evaluation completed, including scans that found issues |
| `1` | Incomplete coverage or an operational error |
| `2` | Invalid command-line usage |

## Docker

```bash
docker build -t awsherlock:local .
docker run --rm --network none awsherlock:local --help
```

Offline demo on macOS/Linux:

```bash
docker run --rm --network none -v "$PWD/examples:/data:ro" awsherlock:local scan /data/demo-snapshot.json --output json
```

Offline demo on PowerShell:

```powershell
docker run --rm --network none --mount "type=bind,source=$((Get-Location).Path)/examples,target=/data,readonly" awsherlock:local scan /data/demo-snapshot.json --output json
```

Example live profile scan on PowerShell:

```powershell
docker run --rm --mount "type=bind,source=$env:USERPROFILE/.aws,target=/home/scanner/.aws,readonly" -e AWS_DEFAULT_REGION=eu-central-1 awsherlock:local scan --profile production --services iam,s3 --output json
```

The image runs as UID `10001`. Mount a writable directory at `/work` to retain reports. On Linux, arrange mount permissions or use `--user` with your UID/GID. Supply credentials at runtime through SDK mechanisms. Host-only credential helpers must also be available inside the container; SSO login/refresh happens outside AWSherlock. No host credentials are copied into the image.

## Security and limitations

AWSherlock reads configuration and never changes AWS resources. It does not fetch secret values, Lambda code or environment values, EC2 user data, or KMS key material.

- Findings are configuration risk indicators, not proof of effective access.
- Policy checks do not simulate conditions, denies, boundaries or SCPs.
- Regional services use one configured region; there is no all-region enumeration.
- Unknown Lambda runtimes and container images produce incomplete runtime coverage.
- Organization snapshot capture and OU/SCP analysis are not supported.
- Validation has used mocked AWS APIs and local browsers; no live-account validation is claimed.

For vulnerability reports, see [SECURITY.md](SECURITY.md).

## Contributing

Bug reports and focused improvements are welcome. Include the command, version, check ID and sanitized reproduction where possible. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and architecture guidance, and [CHANGELOG.md](CHANGELOG.md) for release details.

## License

[MIT](LICENSE).
