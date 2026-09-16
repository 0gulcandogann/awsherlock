# AWSherlock

AWSherlock is a command-line scanner for AWS security configuration. It reads your account's settings, runs 28 checks across seven services, and reports the findings in your terminal, as JSON, or as an HTML file you can open in a browser.

The scanner does not change AWS resources. It uses your existing AWS authentication and records which checks it could actually run. If a permission is missing, the report shows the gap alongside any findings it was able to produce.

```bash
awsherlock scan --profile production
```

**Python 3.11+ · IAM, S3, EC2, Lambda, Secrets Manager, CloudTrail, KMS · MIT**

[Installation](#installation) · [First scan](#first-scan) · [Reports](#reports) · [Checks and permissions](docs/checks.md) · [Troubleshooting](#troubleshooting)

## Installation

Install Python 3.11 or newer and Git before starting. AWSherlock installs into an isolated environment so it can run from any directory without activating a virtual environment. There is no PyPI installation step; install from this repository.

### Windows

Open PowerShell:

```powershell
git clone https://github.com/0gulcandogann/awsherlock.git
cd awsherlock
py -m pip install --user pipx
py -m pipx ensurepath
py -m pipx install .
```

Close and reopen your terminal, then check the installed command:

```powershell
awsherlock --version
awsherlock --help
```

Installation is per user and does not need administrator access. Running `awsherlock` without arguments also displays help and does not contact AWS.

### Linux and macOS

```bash
git clone https://github.com/0gulcandogann/awsherlock.git
cd awsherlock
./install.sh
awsherlock --version
```

The installer creates a Python environment in `~/.local/share/awsherlock/venv` and links the command into `~/.local/bin`. It does not need sudo or change your system Python.

If the command is not found, add the bin directory to PATH:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Add that line to your shell configuration, such as `~/.bashrc` or `~/.zshrc`, to keep it for future terminals. The installer prints the PATH command for your chosen location. Set `PYTHON` to select a Python executable, or `AWSHERLOCK_INSTALL_ROOT` and `AWSHERLOCK_BIN_DIR` to choose other user-owned directories.

On systems that package Python's virtual-environment support separately, install it before running the script. For example, Debian and Ubuntu provide `python3-venv`.

## First scan

AWSherlock uses the standard AWS SDK credential chain. Existing AWS CLI profiles, environment credentials, instance or container roles, and authenticated IAM Identity Center sessions can supply credentials. The AWS CLI is useful for setting up profiles and SSO; it is not required for every scan.

If you use IAM Identity Center, sign in with your configured profile first:

```bash
aws sso login --profile production
awsherlock scan --profile production
```

To use the default credential chain:

```bash
awsherlock scan
```

Set the region in your profile or through `AWS_DEFAULT_REGION`. Regional services use that one configured region. IAM is global, and S3 buckets are inspected in their own regions. There is no `--region` flag or automatic scan of every AWS region.

Your identity needs permission to read the configuration being inspected. See [checks and required permissions](docs/checks.md) before assigning access to an audit role. AWSherlock does not create roles or attach policies for you.

### Choose services

A plain scan selects all seven supported services. To limit the scan, pass a comma-separated list:

```bash
awsherlock scan --profile production --services iam,s3
awsherlock scan --profile production --services ec2,lambda,kms
```

Accepted names are `iam`, `s3`, `ec2`, `lambda`, `secretsmanager`, `cloudtrail`, and `kms`.

## Reading the results

Terminal output starts with finding totals, severity counts, and a coverage table. Findings follow in order of severity. Each card identifies the resource, explains the configuration issue, and gives a remediation suggestion. Collection errors appear in a separate section.

Severity describes the reported configuration risk. Coverage tells you whether the scanner had enough information to evaluate the selected checks. Read both before drawing a conclusion from the results.

| Coverage | Meaning |
| --- | --- |
| `COMPLETE` | Applicable checks on known resources were evaluated. This is not a statement that the account is secure. |
| `PARTIAL` | Some checks ran, but other checks lacked facts or permissions. |
| `ACCESS_DENIED` | Permission denial prevented evaluation for this entry. |
| `ERROR` | Collection or evaluation failed. |
| `NOT_SCANNED` | Required facts were unavailable, or an organization account was not active. |

A failed resource listing can hide resources the scanner never learned about. The count of checks not scanned covers known resources only.

| Exit code | Meaning |
| --- | --- |
| `0` | Evaluation completed. Findings may still exist. |
| `1` | Coverage was incomplete, or an operational error occurred. |
| `2` | The command or its arguments were invalid. |

Exit code `0` does not mean there are no security findings. If a scan is partial, AWSherlock still writes the available report before returning `1`.

## Reports

### HTML

```bash
awsherlock scan --profile production --output html
```

Open `awsherlock-report.html` in your browser. To choose a file name:

```bash
awsherlock scan --profile production --output html --report-file production.html
```

The report uses a light theme with bordered cards. It includes scan metadata, severity counts, findings, evidence, remediation, and coverage details. Use the search field and severity, service, and account filters to narrow the findings. Sorting is available by severity, service, resource, or check ID.

HTML reports are single files with embedded styles and JavaScript. They need no server or internet connection. All findings remain readable with JavaScript disabled.

### JSON

Write structured JSON to stdout:

```bash
awsherlock scan --profile production --output json
```

Or save it directly:

```bash
awsherlock scan --profile production --output json --report-file findings.json
```

JSON includes metadata, summary counts, normalized findings, coverage, and collection issues. `--report-file` is supported for JSON and HTML output. Existing report files are never overwritten; choose a new name or move the earlier report.

## Scan another account

Use a source profile to assume an audit role in the target account:

```bash
awsherlock scan --profile production --role arn:aws:iam::123456789012:role/AWSherlockAuditRole
```

Replace the account ID and role name with your target role. The source identity needs `sts:AssumeRole`, the target role must trust that source, and the role needs the service read permissions listed in [docs/checks.md](docs/checks.md).

If the trust policy requires an external ID, or you want a specific session name:

```bash
awsherlock scan --profile production --role arn:aws:iam::123456789012:role/AWSherlockAuditRole --external-id audit-external-id --role-session-name security-review
```

Temporary credentials stay in memory. Explicit assumed-role credentials do not automatically refresh during a scan. Interactive MFA arguments are not supported; use an already authenticated source session.

## Scan an organization

```bash
awsherlock scan organization --profile management --output html --report-file organization.html
```

The source account needs access to `organizations:ListAccounts` and permission to assume the audit roles in member accounts. AWSherlock discovers accounts and scans active accounts sequentially using `AWSherlockAuditRole` by default.

Choose another role name or path, and limit services if needed:

```bash
awsherlock scan organization --profile management --role-name audit/Reader --services iam,s3 --output html --report-file organization-s3-iam.html
```

Each member role must trust the source identity and allow the required reads. Accounts that cannot be accessed are recorded in the report while scanning continues for the remaining accounts. Non-active accounts are marked `NOT_SCANNED`.

For organization scans, `--external-id` and `--role-session-name` apply to the member-account roles. Use `--role` to assume a source discovery role first. The HTML account filter lets you review findings from one account at a time.

## Capture a snapshot for offline analysis

Collect configuration facts without evaluating security rules:

```bash
awsherlock snapshot --profile production --services iam,s3 --output snapshot.json
```

Evaluate that file later, or generate a report without contacting AWS:

```bash
awsherlock scan snapshot.json
awsherlock scan snapshot.json --output html --report-file offline.html
```

Offline scans use the same rules as live scans. Authentication arguments such as `--profile` and `--role` cannot be used with a snapshot. `--services` can select services already present in the file. Existing snapshot files are never overwritten.

Snapshots reflect the time of collection. They contain account IDs, resource names, policies, and security metadata. Treat snapshots and reports as internal audit data and sanitize them before sharing. Organization snapshot capture is not supported.

## Checks

| Service | Count | Configuration reviewed |
| --- | ---: | --- |
| IAM | 6 | AdministratorAccess, broad policy actions and resources, console MFA, old and unused active keys |
| S3 | 5 | Public access safeguards, default encryption, versioning, access logging, public policy status |
| EC2 | 6 | Internet-wide SSH, RDP and database ingress; IMDSv1; public addresses; EBS encryption |
| Lambda | 3 | Public function URLs, broad managed execution-role policies, deprecated runtimes |
| Secrets Manager | 3 | Rotation, broad resource-policy principals, custom encryption key state |
| CloudTrail | 3 | Usable trail, multi-region and global logging, log validation |
| KMS | 2 | Eligible key rotation, broad key-policy principals |

[Checks and permissions](docs/checks.md) lists the check IDs, finding triggers, required AWS actions, and service-specific limits.

AWSherlock evaluates configuration indicators. It does not prove effective access or simulate policy conditions, explicit denies, permissions boundaries, or SCPs. Unknown Lambda runtimes and container-image runtimes leave runtime coverage incomplete. OU analysis, automatic remediation, and compliance certification are not included.

The scanner does not retrieve secret values, Lambda code or environment values, EC2 user data, or KMS key material. Validation has used mocked AWS APIs and local browsers; live-account validation is not claimed.

## Docker

Build the image from the cloned repository:

```bash
docker build -t awsherlock:local .
docker run --rm awsherlock:local --version
```

For a live scan with a host AWS profile on Linux or macOS:

```bash
docker run --rm -v "$HOME/.aws:/home/scanner/.aws:ro" -e AWS_DEFAULT_REGION=eu-central-1 awsherlock:local scan --profile production --output json
```

On PowerShell:

```powershell
docker run --rm --mount "type=bind,source=$env:USERPROFILE/.aws,target=/home/scanner/.aws,readonly" -e AWS_DEFAULT_REGION=eu-central-1 awsherlock:local scan --profile production --output json
```

To save an HTML report, mount an output directory at `/work`. On Linux or macOS:

```bash
mkdir -p reports
docker run --rm -v "$HOME/.aws:/home/scanner/.aws:ro" -v "$PWD/reports:/work" --user "$(id -u):$(id -g)" -e HOME=/home/scanner -e AWS_DEFAULT_REGION=eu-central-1 awsherlock:local scan --profile production --output html --report-file /work/report.html
```

The image normally runs as UID `10001`. The output mount must be writable by the container user; the command above uses your host UID and GID. The credentials mount must also be readable. Supply authentication at runtime, never during the image build. SSO sessions must already be authenticated, and any external credential helper used by a profile must be available inside the container.

You can also mount your own snapshot read-only and run offline with `--network none`.

## Update or remove

Run the update commands from the directory where you cloned AWSherlock.

For Linux and macOS installs made with the script:

```bash
git pull --ff-only
./install.sh
```

For Windows pipx installs:

```powershell
git pull --ff-only
py -m pipx install --force .
```

Then run `awsherlock --version`. Reinstalling from the updated clone also picks up changes that keep the same version number. `awsherlock --update` is available as a convenience command; if it does not refresh a clone-based pipx install, use the commands above.

To remove a Windows pipx install:

```powershell
py -m pipx uninstall awsherlock
```

For the default Linux/macOS script install, remove the `~/.local/bin/awsherlock` symlink and the `~/.local/share/awsherlock` directory. If you chose custom installation paths, remove those instead. Keep your cloned repository if you want to install again later.

## Troubleshooting

**`awsherlock` is not found.** On Windows, run `py -m pipx ensurepath` and restart the terminal application, including the IDE if you use its terminal. On Linux/macOS, check that your selected bin directory is on PATH. Use `Get-Command awsherlock` in PowerShell or `command -v awsherlock` in a Unix shell to check which command is being found.

**Credentials are missing or expired.** Check your selected profile and sign in again if it uses SSO. AWSherlock does not perform an interactive login. To confirm the source account with the AWS CLI, run `aws sts get-caller-identity --profile production`.

**The report says `AccessDenied`.** Review the specific operation in the collection issues, then compare your role permissions with [docs/checks.md](docs/checks.md). Other checks can still produce findings, but denied checks have not been evaluated.

**A regional service could not be scanned.** Set a region in your profile or through `AWS_DEFAULT_REGION` and rerun. One scan covers one configured region for regional services.

**A report file cannot be created.** Check the output directory and choose a file name that does not already exist. AWSherlock refuses to overwrite reports and snapshots.

For the complete argument list:

```bash
awsherlock --help
awsherlock scan --help
awsherlock snapshot --help
```

## Issues and security reports

For bugs, include the AWSherlock version, the command, the affected check ID, and a sanitized description of what happened. Do not attach credentials or unsanitized reports. See [CONTRIBUTING.md](CONTRIBUTING.md) for contributions and [SECURITY.md](SECURITY.md) for vulnerability reporting.

Release changes are recorded in [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE).
