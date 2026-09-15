# AWSherlock

**AWSherlock** is an open-source AWS security scanner that inspects AWS environments, identifies risky configurations, and generates standalone security reports.

> Status: early development — v0.1

## What AWSherlock will do

AWSherlock is designed to support:

- AWS CLI profiles
- AWS IAM Identity Center / SSO through the standard AWS credential chain
- STS AssumeRole
- AWS Organizations multi-account scanning
- service-specific security checks
- permission coverage reporting
- terminal findings
- JSON reports
- standalone HTML reports

The v0.1 release intentionally stays focused on AWS and read-only security assessment.

## v0.1 target

Target scope:

- IAM
- S3
- EC2 / Security Groups
- Lambda
- Secrets Manager
- CloudTrail
- KMS
- AWS Organizations account discovery

Approximately 30 security checks are planned for v0.1.

## Planned CLI

```bash
awsherlock scan
awsherlock scan --profile production
awsherlock scan --role arn:aws:iam::123456789012:role/AWSherlockAuditRole
awsherlock scan --services iam,s3
awsherlock scan organization
awsherlock scan snapshot.json
```

## Reports

AWSherlock will support:

```text
Console
JSON
Standalone HTML
```

The HTML report will be a self-contained local file with embedded CSS and JavaScript.

No web server will be required.

## Development status

The project follows a 20-working-day v0.1 plan.

Current task:

See [`NOW.md`](NOW.md).

Project specification:

See [`SPEC.md`](SPEC.md).

Codex instructions:

See [`AGENTS.md`](AGENTS.md).

## Development quick-start (Day 2)

Requires Python 3.11 or newer. From the project directory, create a virtual
environment and install the package with development dependencies:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Or on macOS/Linux:

```bash
source .venv/bin/activate
```

Install and run the current CLI:

```bash
python -m pip install -e ".[dev]"
awsherlock --help
awsherlock --version
awsherlock scan --help
awsherlock scan
awsherlock scan --profile production
```

The `scan` command uses the standard boto3 credential chain and calls STS
`GetCallerIdentity` to display account, caller ARN, partition, profile, and region.
Configure credentials using your existing AWS CLI/SDK setup; use `--profile`
to select a named profile. For SSO, sign in with your usual AWS CLI login first.
AWSherlock does not store or print credentials. The region comes from SDK
configuration and is shown as not configured if absent.

Security checks are not implemented yet. Authentication failures exit with code 1;
successful identity resolution does not mean the account passed a security scan.
Other planned CLI features above are not yet implemented. Help and version commands
need no AWS credentials and make no AWS calls. You can also use `python -m awsherlock`
in place of `awsherlock`.

Run the tests (AWS calls are mocked; no real credentials are required):

```bash
python -m pytest
```

## Design principles

- read-only by default
- no custom AWS credential storage
- temporary credentials preferred
- explicit permission coverage
- modular collectors and checks
- standalone reports
- tests for every security rule
- no SaaS or web dashboard in v0.1

## License

MIT
