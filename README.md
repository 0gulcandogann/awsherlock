![AWSherlock](awsherlock.png)

# AWSherlock

AWSherlock is a command-line scanner for AWS security configuration. It reads your account's settings, runs 28 checks across seven services, and reports the findings in your terminal, as JSON, or as an HTML file you can open in a browser.

The scanner does not change AWS resources. It uses your existing AWS authentication and records which checks it could actually run. If a permission is missing, the report shows the gap alongside any findings it was able to produce.

```bash
awsherlock scan --profile production
```

**Python 3.11+ · IAM, S3, EC2, Lambda, Secrets Manager, CloudTrail, KMS · MIT**

[Installation](#installation) · [First scan](#first-scan) · [Reports](#reports) · [Checks and permissions](#checks-and-permissions) · [Troubleshooting](#troubleshooting)

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

Your identity needs permission to read the configuration being inspected. See [checks and required permissions](#checks-and-permissions) before assigning access to an audit role. AWSherlock does not create roles or attach policies for you.

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

Replace the account ID and role name with your target role. The source identity needs `sts:AssumeRole`, the target role must trust that source, and the role needs the service read permissions listed in [checks and permissions](#checks-and-permissions).

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

[Checks and permissions](#checks-and-permissions) lists the check IDs, finding triggers, required AWS actions, and service-specific limits.

AWSherlock evaluates configuration indicators. It does not prove effective access or simulate policy conditions, explicit denies, permissions boundaries, or SCPs. Unknown Lambda runtimes and container-image runtimes leave runtime coverage incomplete. OU analysis, automatic remediation, and compliance certification are not included.

The scanner does not retrieve secret values, Lambda code or environment values, EC2 user data, or KMS key material. Validation includes mocked AWS APIs, local browser checks, and LocalStack integration scenarios; live AWS-account validation is not claimed.

## Checks and permissions

Use these permissions to review the access needed by your audit identity. They describe reads used by the scanner, rather than a ready-to-attach policy. Source identities and target roles also need the STS or Organizations permissions described above.

### S3 scanner

```bash
awsherlock scan --services s3
awsherlock scan --profile production --services s3
awsherlock scan --role arn:aws:iam::123456789012:role/AWSherlockAuditRole --services s3
```

Service names can be combined, for example `--services iam,s3`. The S3 collector lists general-purpose
buckets with pagination, resolves each region, and reads five configurations
through the shared session. Each setting is read once per bucket; regional clients
are reused. Required read permissions:

- `s3:ListAllMyBuckets`
- `s3:GetBucketLocation`
- `s3:GetBucketPublicAccessBlock`
- `s3:GetEncryptionConfiguration`
- `s3:GetBucketVersioning`
- `s3:GetBucketLogging`
- `s3:GetBucketPolicyStatus`

| Check | Finding trigger | Severity |
| --- | --- | --- |
| AWSH-S3-001 | Bucket Block Public Access absent or not fully enabled | MEDIUM |
| AWSH-S3-002 | Default encryption absent or algorithm unrecognized | LOW |
| AWSH-S3-003 | Versioning absent or suspended | MEDIUM |
| AWSH-S3-004 | Server access logging destination absent | LOW |
| AWSH-S3-005 | S3 classifies the bucket policy as public (`IsPublic=true`) | HIGH |

Encryption accepts SSE-S3 (`AES256`), SSE-KMS, and DSSE-KMS, including the AWS-managed
KMS default without an explicit key ID. A missing configuration finding does not
mean objects are unencrypted: [S3 encrypts new uploads automatically](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html).
Existing object encryption and KMS key usability are not inspected.

The policy check uses [S3 GetBucketPolicyStatus](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicyStatus.html)
instead of downloading or interpreting policy documents. It detects S3's public
policy classification, not every unsafe policy or effective access path. No policy
is a valid absence, distinct from an unreadable policy. Logging checks configuration,
not delivery success or alternative CloudTrail coverage.

`AWSH-S3-001` produces a MEDIUM finding when the bucket configuration is absent
or any of its four safeguards is disabled. This identifies potential exposure;
it does not prove anonymous access. Account-level controls, policy documents,
ACLs, access points, and object access are not evaluated. AWS applies the
[most restrictive applicable Block Public Access settings](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html).

Missing configuration is distinct from AccessDenied. Failed or malformed reads
are shown as errors; other checks on the same bucket and remaining buckets continue.
Only checks with successfully collected facts run. Coverage is COMPLETE, PARTIAL,
ACCESS_DENIED, ERROR or NOT_SCANNED; the evaluated check count is displayed.
Errors exit with code 1; completed evaluations exit with code 0 even when findings
exist. Directory buckets are not supported. No settings are changed and no objects
are downloaded.

### IAM scanner

`awsherlock scan --services iam` runs six IAM configuration checks: directly
attached AWS AdministratorAccess, wildcard/complement Allow actions, wildcard/
complement Allow resources, console users without MFA, active keys older than 90
days, and active keys unused for more than 90 days (including never-used keys).
Key IDs are used transiently for API requests and excluded from collected data.

Managed policies use the default version; inline policies are included. IAM is
global and scanned once. Group attachments are reported on the group. Policy
checks are risk indicators, not effective-permission simulation: conditions,
explicit denies, boundaries, and SCPs may restrict access. Wildcard resources
are necessary for some actions. Stale passwords/root credentials are not checked.

Required reads: `iam:GetAccountAuthorizationDetails`, `iam:GetLoginProfile`,
`iam:ListMFADevices`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`.

### EC2 scanner

`awsherlock scan --services ec2` scans the SDK-configured region (configure
`AWS_DEFAULT_REGION` or your profile region). It checks internet-wide SSH, RDP,
and common database ports; IMDSv1; public IPv4/global IPv6 addresses; and EBS
encryption. IPv4/IPv6 CIDRs, port ranges, and protocol -1 are supported. SSH uses
TCP; RDP/database checks include TCP/UDP. Database ports: 1433, 1521, 3306, 5432,
6379, 9042, 9200, 27017. Routing, NACLs, and application exposure are not assessed.
Required reads: `ec2:DescribeSecurityGroups`, `ec2:DescribeInstances`,
`ec2:DescribeVolumes`. Missing region or permissions are visible errors.

### Lambda and Secrets Manager

Use `--services lambda,secretsmanager` in the configured region. Lambda checks
unauthenticated function URLs (including aliases), directly attached AWS
AdministratorAccess/PowerUserAccess execution policies, and deprecated managed
runtimes. Custom/inline role policies require IAM review; URL resource policies
and effective access are not evaluated. Container images and unknown runtimes
produce incomplete coverage. The runtime catalogue is dated 2026-09-15 and must
be maintained against [AWS runtime dates](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html).

Secrets Manager checks rotation, broad Allow principals (including conditional
statements, requiring review), and non-enabled custom KMS keys. Default
aws/secretsmanager encryption is accepted. Conditions and denies are not simulated.
No secret values, function code, or environment variable values enter scan data.

Required reads: `lambda:ListFunctions`, `lambda:ListFunctionUrlConfigs`,
`iam:ListAttachedRolePolicies`, `secretsmanager:ListSecrets`,
`secretsmanager:GetResourcePolicy`, and `kms:DescribeKey` for custom secret keys.

### CloudTrail and KMS

Use `--services cloudtrail,kms`. CloudTrail includes organization and shadow trails,
reads status in the home region, and checks for a usable trail visible in the
configured region, multi-region/global-event settings, and log file validation.
Stopped logging, a missing destination, or reported delivery errors trigger review; this does not inspect event selectors,
CloudTrail Lake, log contents, or every region. Permission failures leave availability
unknown. Requires `cloudtrail:DescribeTrails` and `cloudtrail:GetTrailStatus`.

KMS checks automatic rotation of enabled customer-managed symmetric encryption
keys with AWS_KMS origin, plus broad Allow principals in customer key policies.
AWS-managed, imported, asymmetric, and disabled keys are outside automatic rotation
scope. Standard root delegation and `Resource: "*"` alone do not trigger the policy
check. Conditions/denies may restrict broad statements. Requires `kms:ListKeys`,
`kms:DescribeKey`, `kms:GetKeyRotationStatus`, `kms:GetKeyPolicy`. No key material
or decrypted data is requested.


### Check IDs for the remaining services

| Check | Finding trigger | Severity |
| --- | --- | --- |
| AWSH-IAM-001 | AWS AdministratorAccess directly attached | HIGH |
| AWSH-IAM-002 | Allow statement uses wildcard actions or NotAction | MEDIUM |
| AWSH-IAM-003 | Allow statement uses wildcard resources or NotResource | MEDIUM |
| AWSH-IAM-004 | Console user has no registered MFA device | HIGH |
| AWSH-IAM-005 | Active access key is older than 90 days | MEDIUM |
| AWSH-IAM-006 | Active access key unused for over 90 days, or never used and older than 90 days | MEDIUM |
| AWSH-EC2-001 | Security group permits internet-wide SSH | HIGH |
| AWSH-EC2-002 | Security group permits internet-wide RDP | HIGH |
| AWSH-EC2-003 | Security group permits internet-wide access to a listed database port | HIGH |
| AWSH-EC2-004 | Instance metadata permits IMDSv1 | MEDIUM |
| AWSH-EC2-005 | Instance has public IPv4 or global IPv6 addressing | MEDIUM |
| AWSH-EC2-006 | EBS volume is unencrypted | HIGH |
| AWSH-LAMBDA-001 | Function URL authentication is NONE | HIGH |
| AWSH-LAMBDA-002 | Execution role directly has AWS AdministratorAccess or PowerUserAccess | HIGH |
| AWSH-LAMBDA-003 | Managed runtime is deprecated in the bundled catalogue | MEDIUM |
| AWSH-SECRET-001 | Automatic rotation is disabled | MEDIUM |
| AWSH-SECRET-002 | Resource policy allows a broad principal | MEDIUM |
| AWSH-SECRET-003 | Custom encryption KMS key is not Enabled | MEDIUM |
| AWSH-CT-001 | No usable CloudTrail trail is visible in the scanned region | HIGH |
| AWSH-CT-002 | Multi-region or global service event logging is disabled | MEDIUM |
| AWSH-CT-003 | Log file validation is disabled | MEDIUM |
| AWSH-KMS-001 | Eligible customer key has automatic rotation disabled | MEDIUM |
| AWSH-KMS-002 | Customer key policy allows a broad principal | MEDIUM |

### Validation and limits

The latest local regression run passed 393 tests. A separate LocalStack run collected all seven services without collection errors. All 25 selected secure and insecure fixture resources matched their expected finding sets. Live JSON and independently captured snapshot/offline JSON agreed on findings, coverage and summary. HTML, console output, AssumeRole and actual HTTP permission-denial scenarios were also checked. Denied reads produced incomplete coverage and exit code 1.

Positive scenarios exercised 27 of the 28 checks. IAM key-age and stale-key scenarios used the collector's controlled clock advanced by 91 days. The S3 missing-default-encryption scenario could not be reproduced because the emulator retained automatic encryption after deletion. Pagination and organization multi-account behavior were not validated in that integration run. Lambda execution, secret rotation execution and actual log delivery were not tested.

LocalStack's ready-made AWS-managed policies added findings outside the selected test resources. The 25-resource match count excludes those ambient policies; it is not an overall accuracy score. IAM wildcard findings also need context because some AWS actions require wildcard resources. Emulator validation does not establish identical behavior in a real AWS account.

Test harnesses, fixtures, screenshots, local reports and development notes are kept outside the published repository and package. The commands in this README work with your own AWS profiles or snapshots; no bundled test environment is required.

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

**The report says `AccessDenied`.** Review the specific operation in the collection issues, then compare your role permissions with [checks and permissions](#checks-and-permissions). Other checks can still produce findings, but denied checks have not been evaluated.

**A regional service could not be scanned.** Set a region in your profile or through `AWS_DEFAULT_REGION` and rerun. One scan covers one configured region for regional services.

**A report file cannot be created.** Check the output directory and choose a file name that does not already exist. AWSherlock refuses to overwrite reports and snapshots.

For the complete argument list:

```bash
awsherlock --help
awsherlock scan --help
awsherlock snapshot --help
```

## Issues and contributions

For bugs, include the AWSherlock version, the command, the affected check ID, expected versus actual behavior, and a sanitized reproduction. A false positive or missing detection can be reported in a public issue with synthetic facts. Do not attach credentials or unsanitized snapshots or reports.

For code changes, use Python 3.11 or newer in a virtual environment:

```bash
python -m venv .venv
```

Activate it with `source .venv/bin/activate` on Linux/macOS or `.\.venv\Scripts\Activate.ps1` in PowerShell, then install with `python -m pip install -e .`.

Keep sessions in the authentication layer, AWS reads in collectors, evaluation in rules, and rendering in reporters. Reports must remain standalone and work offline. Do not add AWS write calls, custom credential storage or secret-value retrieval. Keep pull requests focused and describe how you verified the change. Security checks need secure and insecure scenarios plus missing-permission behavior; collectors also need pagination and partial-failure checks. Use synthetic data and review the diff for credentials, local artifacts and unrelated files.

## Security reporting

For a suspected vulnerability in AWSherlock, use the repository's private security reporting option when available, or contact the maintainer through their GitHub profile to arrange a private channel. Do not post credentials, private account data or exploitable sensitive details in a public issue. Include the affected version, a synthetic reproduction and expected versus actual behavior. No response-time or support-period guarantee is currently offered.

Findings are configuration indicators for review. Complete coverage applies only to supported checks and known resources. Treat all reports and snapshots as sensitive audit data.

## Release notes

Version 0.1.0 is the initial release candidate, dated 2026-09-16. It includes the 28 checks, standard SDK authentication, assumed roles, organization scans, offline snapshots, three report formats and visible permission coverage described above. The command scans all supported services by default; running it without arguments displays help without contacting AWS. Python packaging and a non-root Docker image are supported.

Recent changes simplify installation from a clone, add the convenience update command, organize terminal findings into severity-ordered cards, and give HTML reports a light theme with purple borders and orange shadows. Untrusted terminal control and directional formatting characters are shown as visible escapes in terminal results and CLI file messages. JSON and HTML retain the original data. Examples and development artifacts are excluded from the public tree and source distribution.

## License

[MIT](LICENSE).
