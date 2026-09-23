![AWSherlock](https://raw.githubusercontent.com/0gulcandogann/awsherlock/main/awsherlock.png)

# AWSherlock

[![Release v0.1.15](https://img.shields.io/badge/release-v0.1.15-FF9900?style=flat-square)](https://pypi.org/project/awsherlock/0.1.15/)
[![PyPI](https://img.shields.io/pypi/v/awsherlock?style=flat-square&color=FF9900)](https://pypi.org/project/awsherlock/)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)
[![35 security checks](https://img.shields.io/badge/security_checks-35-7C3AED?style=flat-square)](#checks)
[![7 AWS services](https://img.shields.io/badge/AWS_services-7-FF9900?style=flat-square)](#checks)
[![License MIT](https://img.shields.io/badge/license-MIT-64748B?style=flat-square)](https://github.com/0gulcandogann/awsherlock/blob/main/LICENSE)

AWSherlock is a command-line scanner for AWS security configuration. It has 35 registered checks across seven core services: 29 default configuration checks and six opt-in IAM identity governance checks. Reports appear in your terminal, as JSON, or as an HTML file you can open in a browser. Optional identity evidence covers external agents, IAM users, role chains, OIDC workloads and native Bedrock/AgentCore role bindings.

> [!TIP]
> **Install from PyPI.** You can also install AWSherlock directly from [PyPI](https://pypi.org/project/awsherlock/) with `pipx install awsherlock`. See [PyPI installation](#pypi-installation) for pip and upgrade commands.

> [!NOTE]
> **Read-only scanning.** The scanner does not change AWS resources. It uses your existing AWS authentication and records which checks it could actually run. If a permission is missing, the report shows the gap alongside any findings it was able to produce.

```bash
# Scan with an existing AWS profile
awsherlock scan --profile production
```

[Installation](#installation) · [First scan](#first-scan) · [All CLI options](#command-reference) · [Reports](#reports) · [Checks and permissions](#checks-and-permissions) · [Troubleshooting](#troubleshooting)

---

## Installation

Install Python 3.11 or newer. AWSherlock installs into an isolated environment so it can run from any directory without activating a virtual environment. Git is needed only for repository installation or the built-in GitHub updater.

### PyPI installation

[AWSherlock is available on PyPI](https://pypi.org/project/awsherlock/). With pipx installed, run:

```bash
pipx install awsherlock
awsherlock --version
awsherlock --help
```

Alternatively, install with pip in an activated virtual environment:

```bash
python -m pip install awsherlock
```

Git is not required for an index installation. Upgrade an index-based pipx installation with `pipx upgrade awsherlock`; use `python -m pip install --upgrade awsherlock` in a virtual environment. The built-in `awsherlock --update` installs the GitHub `main` source and can include changes beyond the latest PyPI release.

Maintainers: see the [PyPI publishing guide](https://github.com/0gulcandogann/awsherlock/blob/main/docs/publishing.md) for validation and first-publication steps.
Contributors: see [Contributing](docs/contributing.md) and
[Writing a security check](docs/writing-checks.md).

### Windows

Open PowerShell:

```powershell
# Clone the repository
git clone https://github.com/0gulcandogann/awsherlock.git
cd awsherlock

# Install the command in an isolated environment
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
# Clone and install without sudo
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

Set the region in your profile or through `AWS_DEFAULT_REGION`, override it with
`--region`, or select explicit regions with `--regions`. IAM is global, and S3
buckets are inspected in their own regions. Regions are not automatically discovered.

Your identity needs permission to read the configuration being inspected. See [checks and required permissions](#checks-and-permissions) before assigning access to an audit role. AWSherlock does not create roles or attach policies for you.

### Preview a scan

For a terminal-guided live single-account plan, run `awsherlock guide`. It
lists locally configured profiles, lets you choose a profile, a region override
and supported services, then prints the validated preview and an equivalent
`awsherlock scan` command to run. The guide does not authenticate, scan, contact
AWS, create files or change your AWS configuration. It requires an interactive
terminal; scripts should use `scan --preview` with explicit options. Profile
names and configured regions are local metadata, not verified credentials.
The printed command uses PowerShell quoting on Windows and POSIX shell quoting
elsewhere.

```bash
awsherlock guide
```

```bash
awsherlock scan --preview --profile production --services iam,s3
awsherlock scan organization --preview --accounts 123456789012
awsherlock scan facts.json --preview
awsherlock scan --preview --preview-format json --services iam,s3
```

The preview validates local options and shows targets, services, evaluation-only
check/resource selectors, and intended report/snapshot destinations. Live identity,
credentials and organization membership remain unverified; no AWS calls, resource
collection, rule evaluation or output files occur. Offline preview reads snapshot
metadata and checks requested services/checks locally. Preview prints a text plan
even when `--output json` or `html` is selected; it never writes those reports.

For a script that checks scan scope before execution, add `--preview-format json`.
It writes one version-1 JSON object to stdout and no output file. This plan is
separate from findings JSON: `--output` still names the intended report format.
The top-level fields are `schema_version` (integer `1`), `kind` (`scan-preview`),
`mode` (`single-account`, `organization`, or `offline`), and these objects:

| Object | Fields and meaning |
| --- | --- |
| `verification` | `identity` is `unverified` or `snapshot_metadata`; `organization_membership` is `not_discovered` for organization plans, otherwise `null`. |
| `target` | `profile`, `source_role`, `expected_account`, `snapshot_path`, `snapshot_account`, `snapshot_region`, `regions`, `region_source`, `organization_role_name`, `accounts`, `ous`. Snapshot account/region come from saved metadata, not live verification. `region_source` is `explicit`, `sdk_default` or `snapshot_metadata`. |
| `collection` | `services` is the selected list, or the snapshot's saved services offline. |
| `evaluation` | `checks` and `resources` are selected lists or `null` for all; `selectors_affect_collection` is always `false`. |
| `destinations` | `report_format`, intended `report_file` and `snapshot` paths. Paths are not created. |
| `options` | Booleans `external_id_supplied`, `identity_governance_requested` and `request_timeouts_configured`. External ID and inventory contents are never printed. |

`null` means no explicit value or not applicable; it does not confirm an AWS
default. An invalid option exits 2, unreadable/invalid offline snapshot exits 1,
and a valid local plan exits 0. `--preview-format` requires `--preview`; `text`
is the default. JSON output stays uncolored even with `--color always`.

### Choose services

A plain scan selects all seven supported services. To limit the scan, pass a comma-separated list:

```bash
awsherlock scan --profile production --services iam,s3
awsherlock scan --profile production --services ec2,lambda,kms
```

Accepted names are `iam`, `s3`, `ec2`, `lambda`, `secretsmanager`, `cloudtrail`, and `kms`.

### Control the startup display

Interactive scans show the AWSherlock banner and a percentage bar. The percentage
counts finished scan steps; it is not an estimate of remaining time.

```bash
awsherlock scan --no-banner
awsherlock scan --no-progress
```

`--no-banner` hides the logo while keeping the bar. `--no-progress` hides both.

```bash
awsherlock scan --verbose
awsherlock scan --summary-only
awsherlock scan --region eu-west-1
```

`--verbose` writes scan stages and completed work units to stderr, including with
`--no-progress` or redirected output. It does not enable SDK debug logs or print
API payloads. JSON stdout remains unchanged.
`--summary-only` keeps console counts, scan coverage and collection issues while
hiding individual finding cards. Incomplete scans still exit with code 1.
It requires console output and cannot be combined with `--output json` or `html`.

`--region` overrides the SDK region for live regional services, including member
accounts in `scan organization`. Without it, SDK configuration remains in effect.
IAM remains global; S3 still discovers bucket locations rather than filtering
buckets to the selected region. Other regions are outside the regional scan scope.
The option validates syntax, not region availability or account opt-in status;
AWS failures retain incomplete coverage. Offline snapshots cannot use `--region`.
Session region selection uses the standard [Boto3 session API](https://docs.aws.amazon.com/boto3/latest/reference/core/session.html).

```bash
awsherlock scan --expect-account 123456789012 --save-snapshot facts.json
awsherlock scan --regions eu-central-1,eu-west-1 --save-snapshot scan-facts --stats
awsherlock scan organization --regions eu-central-1,eu-west-1 --save-snapshot org-facts
awsherlock scan --connect-timeout 5 --read-timeout 30
awsherlock scan --timeout 30 --color never
awsherlock --color always --list-checks
```

`--expect-account` verifies the authenticated target account before collecting
resources. In organization mode it checks the discovery/source account; member
accounts come from discovery. With `--role` it checks the target role account.
Offline scans check snapshot metadata before evaluating. A mismatch exits with
code 1; malformed IDs fail as usage errors before AWS work.

`--regions` scans explicit, comma-separated regions sequentially using the shared
authenticated session. Repeated regions are removed in order. It cannot be combined
with `--region` or an offline snapshot. IAM and S3 run once per account; regional
coverage is labeled in console, JSON, HTML and SARIF, including denied/skipped accounts.
Identical repeated findings (such as CloudTrail shadow trails) are shown once;
different evidence is retained. Resource/check counts represent collection and
evaluation observations across the selected scopes. Other regions remain outside
the selected scope, and failures retain incomplete coverage and exit code 1.

`--save-snapshot` writes normalized facts, including collection issues, without
another collection pass. A single live scan writes a new JSON file. Organization
or `--regions` scans create a new directory of `ACCOUNT-SCOPE.json` files; replay
an individual file with `awsherlock scan scan-facts/123456789012-eu-west-1.json`.
Destinations must not exist; existing artifacts are never overwritten. Failed
account authentication cannot produce a snapshot. A failed scan can leave the
successfully saved subset in the new directory; review report coverage for omissions.

`--connect-timeout` and `--read-timeout` accept finite positive seconds up to 3600
for socket connection/read requests, including STS, organization discovery and
collector auxiliary calls. Unspecified settings keep SDK defaults. `--timeout`
sets both and cannot be combined with either separate option. Retries can make
total elapsed time longer; these flags are not an overall scan deadline.
The `snapshot` command also supports these timeouts, `--region`, `--expect-account`
and `--color`.

`--stats` writes measured elapsed time and resource/check/finding totals to stderr;
it does not claim to count AWS API calls or alter JSON data.
For live scans, `--measurements-file measurements.json` writes a separate, new
JSON file with SDK invocation counts and collection timing samples by account,
opaque identity scope, region and service. The schema starts at version 1.
An invocation is one SDK operation call, including denied calls, not an HTTP
attempt or retry. Authentication calls are excluded. The file contains no
request/response payloads, credentials or caller ARNs. It is written after
collection even when coverage is incomplete; offline replay and `--preview`
reject the flag. Reports and snapshots keep their existing schemas.

`--color auto|always|never` is available at the top level and on scan/snapshot.
Place it before `--help` or `--version` to style eager output. `auto` detects the
terminal; `always` explicitly allows ANSI colors even when redirected; `never`
disables ANSI styling. `NO_COLOR` disables colors in every mode. Forcing colors
does not enable the progress display on a redirected stream. JSON remains unstyled.
These switches also work with organization and offline snapshot scans. They do
not hide findings, permission failures or incomplete coverage, or change exit codes.

### Inspect the active identity and local profiles

```bash
awsherlock profiles list
awsherlock whoami --profile production
awsherlock whoami --profile production --expect-account 123456789012
```

`whoami` verifies the effective account and principal through the same AWS SDK
session layer used by scanning, without collecting resources. It contacts STS;
credential resolution may also use SSO, credential_process or metadata providers.
Its output shows account ID, principal type, caller ARN, profile and region.
The profile is configuration metadata, not a separately verified source account.
An assumed-role caller ARN is displayed as returned by STS, without inventing an
IAM role path. Identity verification does not prove scanner permission coverage.

`profiles list` shows a table of locally configured profile names and configured regions
(or `unknown`), including profiles defined only in the shared credentials file.
It uses SDK config parsing without resolving credentials, executing a credential
process, checking SSO sessions or contacting AWS. It does not display credential
fields; a listed profile is not proof of a usable login or access to an account.
No profiles or credentials are changed.
The table uses cyan profile names, green known regions and yellow unknown or
unverified state, with a profile count and an explicit `Not verified` identity
column. Region color indicates configured metadata, not authentication success.
Use `--color never` or `NO_COLOR=1` for an uncolored table; redirected output is
uncolored by default.

Live scans now show verified identity and selected scope on stderr before
collection. Organization scans distinguish discovery identity from each verified
target identity. Offline replay labels the account as snapshot metadata and does
not verify a live identity. These summaries remain visible with `--no-progress`
and keep JSON stdout unchanged. Recognized SSO-session failures suggest an
external login command; AWSherlock does not log in automatically.

### Inspect the installation and available checks

```bash
awsherlock --doctor
awsherlock --describe-check AWSH-CT-001
awsherlock --list-checks
awsherlock --list-services
```

`--describe-check ID` shows a supported check's title, service, required normalized
fact, remediation and scope limitations. IDs are case-insensitive; unknown IDs
fail with a usage error. This describes configuration indicators without evaluating
resources. Use `--list-checks` to find IDs.

Terminal output shares one palette: orange headings, cyan information, green
completion/remediation, yellow cautions, red errors and purple borders/badges.
Finding severity remains explicit in text: CRITICAL red, HIGH orange, MEDIUM
yellow, LOW cyan and INFO green. Colors adapt to terminal support; redirected
output is plain by default. Set `NO_COLOR=1` to disable colors. JSON, HTML and snapshot
contents are unaffected by the terminal palette.

These commands do not contact AWS or resolve credentials. `--doctor` shows the
running Python, package location, PATH launcher, dependency versions and terminal
information. Use it when the command appears to run an older installation.
`--list-checks` lists the registered check IDs and titles; `--list-services` shows
each supported service and its check count. Use one action at a time, without a
subcommand.

## Command reference

Every supported option is listed below, including `--help`. Options belong to the
command shown in each table; for example, use `awsherlock --doctor` and
`awsherlock scan --stats`. `--color` is also available on `whoami`, `profiles list` and `guide`.

```bash
awsherlock --help
awsherlock whoami --help
awsherlock profiles list --help
awsherlock guide --help
awsherlock identities --help
awsherlock diff --help
awsherlock scan --help
awsherlock snapshot --help
```

### Top-level options: `awsherlock [OPTIONS]`

| Option | Default | Usage |
| --- | --- | --- |
| `--help` | Off | Show command help and exit without AWS calls. |
| `--version` | Off | Print the installed version and exit without AWS calls. |
| `--update` | Off | Update the installation from GitHub main; requires network access. See [updates](#update-or-remove). |
| `--doctor` | Off | Show allowlisted local installation, dependency and terminal diagnostics; no AWS calls. |
| `--list-checks` | Off | List all 35 registered check IDs and titles; no AWS calls. Six identity governance checks are opt-in. |
| `--list-services` | Off | List supported services and their check counts; no AWS calls. |
| `--describe-check ID` | Not selected | Explain a supported check, required fact, remediation and scope; IDs are case-insensitive. Example: `AWSH-CT-001`. No AWS calls. |
| `--color MODE` | `auto` | `auto`, `always` or `never`; honors `NO_COLOR`. Place before eager `--help`/`--version` to style them. |

Choose one of `--update`, `--doctor`, `--list-checks`, `--list-services` or
`--describe-check`; these actions cannot be combined with each other or with a
subcommand. `--version` exits eagerly rather than running other actions.

### Identity options: `awsherlock whoami [OPTIONS]`

| Option | Default | Usage |
| --- | --- | --- |
| `--profile NAME` | SDK credential chain | Select an AWS profile. |
| `--role ARN` | Not selected | Assume this IAM role before STS identity verification. |
| `--role-session-name NAME` | `AWSherlock` when assuming a role | Requires `--role`. |
| `--external-id ID` | Not selected | Trust-policy external ID; requires `--role` and is not displayed. |
| `--region REGION` | SDK configuration | Select the SDK region. |
| `--expect-account ID` | Not selected | Require this 12-digit verified account; mismatch exits 1 without identity output. |
| `--timeout SECONDS` | SDK defaults | Set both socket timeouts, greater than 0 and at most 3600; not an overall deadline. |
| `--color MODE` | `auto` | `auto`, `always` or `never`. |
| `--help` | Off | Show help without authentication. |

Successful verification exits 0; session failures exit 1; invalid options exit 2.
This command produces human-readable diagnostics, not a findings report.

### Profile options: `awsherlock profiles list [OPTIONS]`

| Option | Default | Usage |
| --- | --- | --- |
| `--color MODE` | `auto` | `auto`, `always` or `never`. |
| `--help` | Off | Show local profile command help. |

Missing config files or an empty profile list are normal (exit 0); unreadable or
malformed configuration exits 1 with a sanitized error. SDK configuration paths,
including `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE`, are respected.

### Guided setup options: `awsherlock guide [OPTIONS]`

| Option | Default | Usage |
| --- | --- | --- |
| `--color MODE` | `auto` | `auto`, `always` or `never`. |
| `--help` | Off | Show guide help without reading profiles. |

The guide requires an interactive terminal. It prints a local scan preview and
an equivalent command, then exits without scanning.

### Compare saved snapshots: `awsherlock diff BEFORE AFTER [OPTIONS]`

Compare two normalized snapshot JSON files locally:

```bash
awsherlock diff before.json after.json
awsherlock diff before.json after.json --output json
```

`NEW` means a finding appears in the later snapshot and the earlier service
coverage was complete. `RESOLVED` means a finding is absent later and that
service's later coverage was complete. A finding seen in both is `UNCHANGED`.
Missing/denied service coverage or changed account/region scope makes an
unmatched finding `UNKNOWN`, never `RESOLVED`. These statuses describe observed
scanner findings, not verified remediation or effective AWS access. The
comparison is intentionally conservative: a partial service can make an
unrelated resource change unknown. No AWS calls or output files occur.

`--output json` emits a version-1 `snapshot-diff` document with snapshot IDs,
scope, service coverage, status counts and changes. It omits raw finding
evidence and credentials. Exit 0 means both files were compared, including
comparisons with unknown coverage; invalid options exit 2 and unreadable or
invalid snapshots exit 1. This command does not apply suppression or CI
thresholds.

### Offline identity view: `awsherlock identities SNAPSHOT [OPTIONS]`

Read IAM role/user summaries from an existing normalized snapshot without AWS
calls or file writes. Example: `awsherlock identities identity-facts.json`.
Console output includes identities and collection coverage; an empty IAM
inventory is stated explicitly. `--output json` prints a separate version-1
identity-view document with `schema_version`, `kind`, `account_id`, `coverage`
and `identities`. It is not the scan report schema. `--color` accepts `auto`,
`always` or `never`. The command exits 0 for complete coverage and 1 for
incomplete coverage or input errors. The snapshot must contain IAM; old
snapshots lacking governance facts remain incomplete, not empty proof of safety.

`--view ai|unowned|stale|shared` filters displayed identities while keeping full
IAM coverage. `ai` matches explicit AI declarations or native Bedrock/AgentCore
bindings, never identity names or User-Agent guesses; `unowned` and `stale`
match existing IAM-007 and IAM-009 review findings; `shared` matches an
explicit shared declaration. For example,
`awsherlock identities identity-facts.json --view stale --output json` emits a
version-2 identity-view document with `view`, `total_identities` and
`matched_identities` in addition to the version-1 fields. The default `all`
view keeps version 1. No match is not proof that no such identities exist:
missing facts, limited usage windows and incomplete coverage still matter.

### Scan options: `awsherlock scan [OPTIONS] [snapshot_path]`

Omit `snapshot_path` for a live account scan, use `organization` for discovered
member accounts, or pass a normalized JSON file for offline evaluation.
`awsherlock scan --help` groups options by target, selection, identity evidence,
reports and execution. It works locally without contacting AWS.
On narrow terminals, Typer may shorten long labels; the table below lists every
option name in full.

| Option | Default | Usage |
| --- | --- | --- |
| `--help` | Off | Show scan help without contacting AWS. |
| `--profile NAME` | SDK credential chain | Use a named AWS profile for live authentication. |
| `--role ARN` | No assumed role | Assume an IAM role for a single-account scan, or for organization discovery/source authentication. |
| `--role-session-name NAME` | `AWSherlock` | Name the assumed-role session; requires `--role` in a single-account scan. In organization mode, applies to member-account roles. |
| `--external-id ID` | Not supplied | External ID for the assumed role; requires `--role` in a single-account scan. In organization mode, applies to member-account roles. |
| `--services LIST` | All seven services | Comma-separated supported service names. Offline selection must exist in the snapshot. |
| `--checks LIST` | All checks | Evaluate comma-separated registered IDs, such as `AWSH-S3-001,AWSH-S3-003`. Collection is unchanged; IDs must belong to the selected services/snapshot. Excluded checks remain visible in coverage. |
| `--accounts LIST` | All discovered accounts | Organization-only: scan comma-separated 12-digit IDs. Discovery still lists all accounts; excluded and undiscovered requested accounts are `NOT_SCANNED`. |
| `--ous LIST` | No OU restriction | Organization-only: comma-separated OU IDs and all descendants; intersects `--accounts`. Requires paginated `organizations:ListChildren`. Failed membership discovery prevents role assumption for uncertain accounts. |
| `--resources LIST` | All discovered resources | Evaluate exact comma-separated resource IDs or ARNs, case-sensitive; collection/saved snapshots remain unchanged. No wildcards or tags. Exclusions and unmatched selectors remain visible; works offline. |
| `--preview` | Off | Validate and print a local scan plan without AWS calls, rule evaluation or output files. Offline mode reads snapshot metadata. Identity and organization membership remain unverified. |
| `--preview-format FORMAT` | `text` with `--preview` | `text` or version-1 `json`; requires `--preview`. Independent of `--output`, which still describes the intended findings report. |
| `--identity-governance` | Off | Collect IAM role/user ownership, purpose, trust, usage and joined policy evidence, plus regional Lambda/EC2 role bindings. Live scans require IAM in `--services`; offline scans expose missing facts. Saved governance evidence is evaluated automatically. |
| `--identity-inventory FILE` | Not supplied | Version-1 exact ARN declarations/approvals; requires `--identity-governance`. Works live/offline. Missing, partial or out-of-scope approval evidence remains unknown. |
| `--identity-events` | Off | Live opt-in regional CloudTrail management-event attribution, including role chains. Requires `--identity-governance`. No raw events or credential identifiers are exported. |
| `--identity-ai-services` | Off | Live Bedrock/AgentCore execution-role metadata through the shared session; requires `--identity-governance`. No agent invocation or prompt/model-log reads. |
| `--identity-analyzers` | Off | Read active findings from existing regional Access Analyzer instances. Requires live `--identity-governance`; never creates analyzers or query jobs. |
| `--identity-days N` | 30 | CloudTrail lookback, 1–90 days; a non-default value requires `--identity-events`. |
| `--identity-max-pages N` | 20 | Evidence page/read budget, 1–1000, shared across regions within each supplemental collector. Requires live `--identity-governance`. |
| `--identity-max-seconds N` | 60 | Evidence time budget between requests, 1–3600 seconds, within each supplemental collector. In-flight SDK timeouts/retries may exceed it. Requires live `--identity-governance`. |
| `--output FORMAT` | `console` | `console`, `json`, `html` or `sarif`. JSON/SARIF goes to stdout unless `--report-file` is supplied. HTML defaults to a new `awsherlock-report.html`. |
| `--report-file PATH` | Not supplied | Write a new JSON/HTML/SARIF report; requires `--output json`, `--output html` or `--output sarif`. Existing files are not overwritten. |
| `--role-name NAME` | `AWSherlockAuditRole` | Member-account role name/path, such as `audit/Reader`; only valid with `scan organization`. |
| `--no-progress` | Off | Hide the banner and progress bar; explicit `--verbose` messages still appear. |
| `--no-banner` | Off | Hide the banner while retaining interactive progress. |
| `--verbose` | Off | Write sanitized scan stages and work units to stderr; does not enable raw SDK debug logging. |
| `--summary-only` | Off | Console totals, coverage and issues without individual finding cards; requires console output. |
| `--region REGION` | SDK-configured region | Select one live region for regional services. Mutually exclusive with `--regions`. |
| `--regions LIST` | Not selected | Explicit comma-separated live regions, deduplicated in order; IAM/S3 run once per account. Mutually exclusive with `--region`. |
| `--expect-account ID` | Not supplied | Require the resolved 12-digit target account ID. Organization mode checks the discovery/source account; offline mode checks snapshot metadata. |
| `--save-snapshot PATH` | Off | Live scans only. Write a new file for a single-account scan, or a new directory for organization/`--regions` scans. Destination must differ from the report path. |
| `--connect-timeout SECONDS` | SDK default | Finite positive socket connection timeout, at most 3600 seconds. |
| `--read-timeout SECONDS` | SDK default | Finite positive socket read timeout, at most 3600 seconds. |
| `--timeout SECONDS` | SDK defaults | Set both request timeouts; cannot be combined with either separate timeout flag. Not an overall scan deadline. |
| `--color MODE` | `auto` / inherited top-level preference | Override terminal colors with `auto`, `always` or `never`. JSON payloads remain unstyled. |
| `--stats` | Off | Write measured elapsed time and resource/check/finding counts to stderr; no API-call count claims. |
| `--measurements-file PATH` | Off | Live scans only: write version-1 SDK invocation counts and collection timing samples to a new JSON file, separate from reports and snapshots. Authentication calls and HTTP retries are excluded. |

Offline scans reject authentication options (`--profile`, `--role`,
`--role-session-name`, `--external-id`), regional selection, request timeouts and
`--save-snapshot` and `--measurements-file`. They support service selection,
account verification, report formats and display/statistics options.
`--role-name` is organization-only.

```bash
# Live: verify account, select regions, retain facts and write an HTML report
awsherlock scan --profile production --expect-account 123456789012 --regions eu-central-1,eu-west-1 --save-snapshot scan-facts --output html --report-file audit.html --timeout 30 --stats

# Organization: assume a configurable member-account role
awsherlock scan organization --profile audit --role-name audit/Reader --role-session-name audit-session --external-id configured-trust-id --regions eu-central-1,eu-west-1

# Offline: show only a compact console summary from one saved scope
awsherlock scan scan-facts/123456789012-eu-west-1.json --summary-only --no-progress --color never
```

Replace the account ID, profile and role trust values with your actual configuration.
Explicit exclusions make coverage incomplete and retain exit code 1. These selectors
do not suppress findings after scanning. Exact resource ID/ARN and descendant OU selection are implemented; tag selection remains deferred.

```bash
awsherlock scan facts.json --checks AWSH-S3-001,AWSH-S3-003 --output json
awsherlock scan organization --accounts 123456789012,999999999999 --services iam,s3
awsherlock scan organization --ous ou-abcd-12345678 --services iam,s3
awsherlock scan facts.json --resources arn:aws:s3:::example-bucket --output json
```
Saved directories contain individually replayable files; pass a file, not the
directory, to offline `scan`. Coverage and error exit codes remain visible in all modes.

### Snapshot options: `awsherlock snapshot [OPTIONS]`

This command collects one live account's normalized facts without evaluating
security rules. `--output` is required and always names a JSON snapshot file;
it is different from scan's `--output FORMAT`.

| Option | Default | Usage |
| --- | --- | --- |
| `--help` | Off | Show snapshot help without contacting AWS. |
| `--output PATH` | Required | Write a new normalized JSON snapshot file; existing files are not overwritten. |
| `--services LIST` | All seven services | Select supported services using a comma-separated list. |
| `--profile NAME` | SDK credential chain | Authenticate with a named AWS profile. |
| `--role ARN` | No assumed role | Assume this IAM role before collecting facts. |
| `--role-session-name NAME` | `AWSherlock` | Set the role session name; requires `--role`. |
| `--external-id ID` | Not supplied | External ID required by the role trust policy; requires `--role`. |
| `--region REGION` | SDK-configured region | Override the region for regional services. IAM remains global; S3 uses bucket locations. |
| `--expect-account ID` | Not supplied | Stop before collection if the resolved account differs from this 12-digit ID. |
| `--connect-timeout SECONDS` | SDK default | Finite positive socket connection timeout, at most 3600 seconds. |
| `--read-timeout SECONDS` | SDK default | Finite positive socket read timeout, at most 3600 seconds. |
| `--timeout SECONDS` | SDK defaults | Set both request timeouts; cannot be combined with either separate timeout flag. |
| `--color MODE` | `auto` / inherited top-level preference | `auto`, `always` or `never`; honors `NO_COLOR`. |

```bash
awsherlock snapshot --output facts.json --profile production --services iam,s3,ec2 --region eu-central-1 --expect-account 123456789012 --timeout 30
awsherlock scan facts.json --output html --report-file offline-audit.html
```

Snapshot does not accept scan-only `--regions`, `--save-snapshot`, `--role-name`,
`--stats`, `--verbose`, `--summary-only`, `--no-banner`, `--no-progress` or
`--report-file`. For organization or multi-region fact capture, use
`awsherlock scan ... --save-snapshot PATH` instead.

## Reading the results

Terminal output starts with finding totals, severity counts, and a coverage table. Findings follow in order of severity. Each card identifies the resource, explains the configuration issue, and gives a remediation suggestion. Scan issues, including collection errors, appear in a separate section.

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

> [!IMPORTANT]
> Exit code `0` does not mean there are no security findings. If a scan is partial, AWSherlock still writes the available report before returning `1`.

## Reports

| Terminal | HTML | JSON | SARIF |
| --- | --- | --- | --- |
| Review findings while scanning | Explore findings in your browser | Process structured scan data | Exchange findings with SARIF readers |
| Severity-ordered cards and coverage | Search, filters, evidence and remediation | Metadata, findings and collection issues | Logical AWS resource locations and full coverage properties |
| Default output | `--output html` | `--output json` | `--output sarif` |

### HTML

```bash
# Generate a standalone browser report
awsherlock scan --profile production --output html
```

Open `awsherlock-report.html` in your browser. To choose a file name:

```bash
awsherlock scan --profile production --output html --report-file production.html
```

The report uses a light theme with bordered cards. It includes scan metadata, severity counts, findings, evidence, remediation, and coverage details. Use the search field and severity, service, and account filters to narrow the findings. Sorting is available by severity, service, resource, or check ID.

> [!TIP]
> HTML reports are single files with embedded styles and JavaScript. They need no server or internet connection. All findings remain readable with JavaScript disabled.

### JSON

Write structured JSON to stdout:

```bash
awsherlock scan --profile production --output json
```

Or save it directly:

```bash
awsherlock scan --profile production --output json --report-file findings.json
```

JSON includes metadata, summary counts, normalized findings, coverage, and collection issues. `--report-file` is supported for JSON, HTML and SARIF output. Existing report files are never overwritten; choose a new name or move the earlier report.

### SARIF

Export existing findings as [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html):

```bash
awsherlock scan facts.json --output sarif --report-file findings.sarif
```

Each finding becomes a result with its check ID and a logical AWS resource
location. AWS resources are not source files, so no physical file/line location
is fabricated. The run's `properties.coverage` and `properties.incomplete` retain
all coverage states, even when results are empty. This is a report conversion,
not GitHub code-scanning integration, and it omits raw finding evidence. The
existing incomplete-scan exit code remains `1`; complete scans exit `0` even
when findings exist.

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

The source account needs access to `organizations:ListAccounts` and permission to assume the audit roles in member accounts. With `--ous`, it also needs `organizations:ListChildren` to discover descendant OUs/accounts. OU and account selectors intersect; excluded accounts remain visible. If any OU branch fails, OU membership is treated as unverified and no selected member roles are assumed. AWSherlock discovers accounts and scans active accounts sequentially using `AWSherlockAuditRole` by default.

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

Snapshots reflect the time of collection. They contain account IDs, resource names, policies, and security metadata. Treat snapshots and reports as internal audit data and sanitize them before sharing. Organization scans can save per-account/scope snapshots with `scan organization --save-snapshot`; replay individual files, not the directory.

## Checks

| Service | Count | Configuration reviewed |
| --- | ---: | --- |
| IAM | 12 | Six default policy/credential checks; six opt-in ownership, purpose, stale role, trust and approval checks |
| S3 | 5 | Public access safeguards, default encryption, versioning, access logging, public policy status |
| EC2 | 6 | Internet-wide SSH, RDP and database ingress; IMDSv1; public addresses; EBS encryption |
| Lambda | 3 | Public function URLs, broad managed execution-role policies, deprecated runtimes |
| Secrets Manager | 3 | Rotation, broad resource-policy principals, custom encryption key state |
| CloudTrail | 4 | Usable trail, multi-region/global logging, log validation and management-event read/write or source gaps |
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
- `s3:GetAccountPublicAccessBlock` (account context through S3 Control)
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
it does not prove anonymous access. Account Block Public Access is read once per
collection and attached as normalized context. Findings show bucket, account and
combined flags (logical OR per safeguard); the bucket finding remains even if
account safeguards compensate. Missing account permission or old snapshots without
account facts remain partial. Policy documents, ACLs, access points, and object
access are not evaluated. AWS applies the
[most restrictive applicable Block Public Access settings](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html).

Missing configuration is distinct from AccessDenied. Failed or malformed reads
are shown as errors; other checks on the same bucket and remaining buckets continue.
If a bucket fact is unavailable, its coverage issue names the affected S3 check
and fact. It points to a matching bucket read failure when one is recorded;
otherwise the fact is absent from the snapshot. Confirmed absent configurations
remain evaluable. Account Block Public Access context has its own separate issue.
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
For the six core checks, a missing normalized fact names its check ID in
coverage. A matching per-resource policy, console-MFA or key-last-used failure
is reported separately; otherwise the fact is absent from the snapshot.
Inactive keys are excluded from the stale-key check. Key IDs and raw policy
documents are not included in these explanations.

### Identity governance and AI attribution

Start with IAM governance, then opt into additional evidence:

```bash
awsherlock scan --services iam --region eu-central-1 --identity-governance
awsherlock scan --services iam --regions eu-central-1,eu-west-1 --identity-governance --identity-inventory identities.json --identity-events --identity-ai-services --identity-analyzers --save-snapshot identity-facts
awsherlock scan identity-facts/123456789012-global-bucket.json --identity-governance --identity-inventory identities.json --output html --report-file identities.html
```

The JSON report contains an `identities` inventory; console and standalone HTML
show classification, approval and observed connection mechanisms. HTML includes
the normalized trust, policy source, usage, workload and event evidence. Excluded
identities remain visible with `NOT_SCANNED` evaluation scope. Saved evidence is
replayed offline without AWS calls; requesting governance on old snapshots exposes
missing facts. Governance capture uses `scan --save-snapshot`.
Use `awsherlock identities SNAPSHOT` for the same normalized identity inventory
as a dedicated offline console or JSON view. It does not resolve credentials.
Missing owner/profile, role usage/trust or approval facts name the affected
governance check in coverage. If a managed-policy or group join is incomplete,
IAM-002/003 remain incomplete even when no broad grant was found in known
statements. Confirmed broad grants are still reported; incomplete joins never
establish that no other broad grants exist.

| Check | Finding trigger | Severity |
| --- | --- | --- |
| AWSH-IAM-007 | Owner absent from `Owner` tag and supplied declaration | MEDIUM |
| AWSH-IAM-008 | Purpose absent from `Purpose` tag and supplied declaration | MEDIUM |
| AWSH-IAM-009 | Role last used over 90 days ago, or over-90-day-old role with no recorded use in the tracking window | MEDIUM |
| AWSH-IAM-010 | Supported trust is broad, including OIDC without exact provider audience/subject restrictions | HIGH |
| AWSH-IAM-011 | Identity absent from a complete approval inventory for its account | MEDIUM |
| AWSH-IAM-012 | Supported role trust or observed caller differs from approvals, or declared required trust controls are missing | HIGH |

Service-linked roles are excluded from ownership, purpose and stale-role checks.
The tag convention is `Owner`, `Purpose`, and optional `IdentityType` with values
`ai`, `workload`, `human` or `unknown`. Only tag presence/kind is retained; arbitrary
tag values are not exported. Governance joins managed policy default versions and
user group grants to their identities; unresolved associations remain partial.
Broad grants are review indicators. Boundaries, denies and organization controls
can restrict effective permissions; IAM role age/usage does not prove an identity
can be safely retired. [RoleLastUsed](https://docs.aws.amazon.com/IAM/latest/APIReference/API_RoleLastUsed.html)
covers at most the trailing 400 days and may cover less in some regions.

An `identities.json` declaration file uses this exact version-1 schema:

```json
{
  "schema_version": 1,
  "accounts": ["123456789012"],
  "complete": false,
  "identities": [
    {
      "arn": "arn:aws:iam::123456789012:role/invoice-agent",
      "kind": "ai",
      "owner": "finance-platform",
      "purpose": "invoice processing",
      "allowed_principals": ["arn:aws:iam::999999999999:role/integration"],
      "shared": false,
      "external_id_required": true,
      "source_identity_required": false
    }
  ]
}
```

`external_id_required` and `source_identity_required` are optional booleans,
defaulting to false. Required controls must cover every supported role-assumption
Allow branch. ExternalId is integration-specific and is not an AI identifier;
its value is never exported. Approval principal values are exact AWS accounts,
IAM principal/provider ARNs or AWS service principals; no wildcard declarations.
`complete: true` asserts that the supplied list contains every approved identity
in the listed accounts. Absence from a partial/out-of-scope list stays unknown.
An unregistered identity is a governance mismatch, not proof of compromise.
Missing inventory leaves approval checks `NOT_SCANNED` and coverage incomplete.
The file stores governance declarations, never AWS credentials.

Connection evidence covers five branches:

- Same/cross-account role callers and observed role chains; missing source events
  retain issuer-only, account-only or incomplete-chain attribution.
- IAM users, long-lived-key metadata and temporary federated-user issuers.
- OIDC/federation: supported provider-specific exact audience/subject constraints;
  unsupported condition shapes remain unknown. CI workloads are not automatically AI.
- Lambda/EC2 role bindings and optional Bedrock/AgentCore native AI bindings.
- Declared shared human/agent identities and intermediary applications: the AWS
  signer may be known while the individual application actor remains unresolved.

`declared_ai` comes from the supplied inventory or `IdentityType` tag;
`verified_ai_binding` comes from a native agent resource's execution-role metadata.
Neither identifies every session of a reused role as AI execution. Ordinary
compute bindings prove workload association, not AI purpose. Names, IP changes,
SDK user agents, sourceIdentity presence and permitted Bedrock actions alone do
not prove AI use. Unknown classification is explicit.

Event evidence uses [CloudTrail LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html),
with regional management history limited to 90 days and logical requests spaced
at least 0.55 seconds apart per region. It does not read data-event logs, so model
invocations and object accesses may be outside this evidence. Page/time truncation,
unsupported/unmapped actors and denied reads remain visible. Empty history does
not prove non-use. Request budgets are checked between calls; configure socket
timeouts for in-flight requests. Credential/session identifiers are correlated
only in memory; raw events, ExternalId/sourceIdentity values and key IDs are not
exported. Native detail SDK responses are reduced immediately to role bindings;
instructions, environment values, code and model content are not retained/reported.

Additional read permissions, according to enabled evidence:

| Evidence | IAM actions |
| --- | --- |
| IAM profiles/policy joins | `iam:ListRoleTags`, `iam:ListUserTags`, `iam:GetPolicy`, `iam:GetPolicyVersion`, in addition to the IAM reads above |
| Workload bindings | `lambda:ListFunctions`, `ec2:DescribeInstances`, `iam:GetInstanceProfile` |
| Audit history | `cloudtrail:LookupEvents` |
| Native AI bindings | `bedrock:ListAgents`, `bedrock:GetAgent`, `bedrock-agentcore:ListAgentRuntimes`, `bedrock-agentcore:GetAgentRuntime` |
| Existing analyzer evidence | `access-analyzer:ListAnalyzers`, `access-analyzer:ListFindings`, `access-analyzer:GetFinding` (the latter two authorize V2 reads too) |

Analyzer imports retain active finding type/status, update time, tracking window,
unused services/actions and supported external principals. Absence, errors and
inactive analyzers remain visible; AWSherlock never creates one or changes access.
Existing unused-access analyzers have [AWS charges](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html).
Findings remain configuration/usage indicators rather than automatic deletion or
effective-permission decisions. No live agent is executed during scanning.

### EC2 scanner

`awsherlock scan --services ec2` scans the SDK-configured region (configure
`AWS_DEFAULT_REGION` or your profile region). It checks internet-wide SSH, RDP,
and common database ports; IMDSv1; public IPv4/global IPv6 addresses; and EBS
encryption. IPv4/IPv6 CIDRs, port ranges, and protocol -1 are supported. SSH uses
TCP; RDP/database checks include TCP/UDP. Database ports: 1433, 1521, 3306, 5432,
6379, 9042, 9200, 27017. Routing, NACLs, and application exposure are not assessed.
Required reads: `ec2:DescribeSecurityGroups`, `ec2:DescribeInstances`,
`ec2:DescribeVolumes`. Missing region or permissions are visible errors.
If a discovered resource has invalid ingress, metadata, address or encryption
data, its valid facts remain evaluable while the affected `AWSH-EC2` checks
are marked incomplete with a RequiredFact coverage explanation. An instance's
metadata and public-address facts are handled independently. Discovery failures
before a resource ID is known remain collection issues, not passing checks.

### Lambda and Secrets Manager

Use `--services lambda,secretsmanager` in the configured region. Lambda checks
unauthenticated function URLs (including aliases), directly attached AWS
AdministratorAccess/PowerUserAccess execution policies, and deprecated managed
runtimes. Custom/inline role policies require IAM review; URL resource policies
and effective access are not evaluated. Container images and unknown runtimes
produce incomplete coverage. The runtime catalogue is dated 2026-09-15 and must
be maintained against [AWS runtime dates](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html).
Missing URL, attached-role-policy or managed-runtime facts name the affected
`AWSH-LAMBDA` check in coverage. A matching per-function collection issue is
reported separately; otherwise the fact is absent from the snapshot. Missing
facts, including unsupported image runtimes, are never treated as passing checks.

Secrets Manager checks rotation, broad Allow principals (including conditional
statements, requiring review), and non-enabled custom KMS keys. Default
aws/secretsmanager encryption is accepted. Conditions and denies are not simulated.
No secret values, function code, or environment variable values enter scan data.
If rotation, policy or encryption metadata is missing, coverage names the affected
`AWSH-SECRET` check and required fact. A matching per-secret collection failure is
reported separately; otherwise the fact is absent from the snapshot. Missing
facts are never treated as passing checks.

Required reads: `lambda:ListFunctions`, `lambda:ListFunctionUrlConfigs`,
`iam:ListAttachedRolePolicies`, `secretsmanager:ListSecrets`,
`secretsmanager:GetResourcePolicy`, and `kms:DescribeKey` for custom secret keys.

### CloudTrail and KMS

Use `--services cloudtrail,kms`. CloudTrail includes organization and shadow trails,
reads status in the home region, and checks for a usable trail visible in the
configured region, multi-region/global-event settings, log file validation and
management-event selectors (`AWSH-CT-004`). Usability requires applicable regional
coverage and management events in addition to logging and no reported delivery error.
Basic ReadWriteType and advanced eventCategory/readOnly selectors are supported, along
with documented trail eventSource NotEquals exclusions for `kms.amazonaws.com`
and `rdsdata.amazonaws.com`. Unsupported source/name/resource filters remain
unknown/partial. Facts preserve whether read and write management events are
selected by any supported selector, plus source exclusions common to every
management-enabled selector. `AWSH-CT-004` reports a missing read/write class or
known source exclusion. Per-source read/write combinations are not simulated;
a positive indicator does not prove all API events are logged.
Old snapshots remain readable; absent selector facts count as NOT_SCANNED.
Snapshots with a positive management indicator but no source or read/write context
cannot complete `AWSH-CT-004`; coverage remains partial.
For selected CloudTrail checks, coverage issues name the check ID and missing
fact. If a related collection issue exists, inspect that operation for denial or
failure; otherwise the fact is absent from the snapshot. These explanations do
not add findings or turn unknown facts into a PASS.
CloudTrail Lake, log contents, actual delivery and every region are not inspected.
Requires `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` and
[`cloudtrail:GetEventSelectors`](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetEventSelectors.html).
Without the new read permission, coverage remains partial.

Within one multi-region scan, successful status/selector reads for the same trail
are reused at its home region. Failures are not cached, and later scans read again.

KMS checks automatic rotation of enabled customer-managed symmetric encryption
keys with AWS_KMS origin, plus broad Allow principals in customer key policies.
AWS-managed, imported, asymmetric, and disabled keys are outside automatic rotation
scope. Standard root delegation and `Resource: "*"` alone do not trigger the policy
check. Conditions/denies may restrict broad statements. Requires `kms:ListKeys`,
`kms:DescribeKey`, `kms:GetKeyRotationStatus`, `kms:GetKeyPolicy`. No key material
or decrypted data is requested.
For a discovered key, missing rotation or policy facts name the affected
`AWSH-KMS` check in coverage. A matching per-key read failure is reported
separately; otherwise the fact is absent from the snapshot. Keys that cannot
be described remain collection issues, not passing checks. AWS-managed keys
remain outside the key-policy check.


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
| AWSH-CT-004 | Management read/write events or supported KMS/RDS Data API sources are excluded | MEDIUM |
| AWSH-KMS-001 | Eligible customer key has automatic rotation disabled | MEDIUM |
| AWSH-KMS-002 | Customer key policy allows a broad principal | MEDIUM |

### Validation and limits

The latest recorded local regression checkpoint passed 794 tests (2026-09-17); this is unit/mocked regression evidence, not real-AWS validation. The [35-check validation matrix](https://github.com/0gulcandogann/awsherlock/blob/main/docs/validation-matrix.md) and [pilot guide](https://github.com/0gulcandogann/awsherlock/blob/main/docs/pilot.md) define the next validation work. All checks remain untested in real AWS for this pilot.

A historical LocalStack run for the earlier 28-check baseline collected all seven services without collection errors. All 25 selected secure and insecure fixture resources matched their expected finding sets. Live JSON and independently captured snapshot/offline JSON agreed on findings, coverage and summary. HTML, console output, AssumeRole and actual HTTP permission-denial scenarios were also checked. Denied reads produced incomplete coverage and exit code 1.

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

Alternatively, update directly from GitHub main (internet required):

```bash
awsherlock --update
awsherlock --version
```

Reinstalling from the updated clone also picks up changes that keep the same version number. If `awsherlock --update` does not refresh a clone-based pipx install, use the platform-specific commands above. Run update as a standalone command, without `scan` or other top-level actions. These instructions also appear in `awsherlock --help` and when running `awsherlock` without arguments.

`--update` displays the installer logs directly. Ctrl+C cancels the update with exit code 130. The Quick start examples in `awsherlock --help` and the bare command are displayed in a bordered command/description table.

The updater forces reinstallation so GitHub main changes are installed even when the package version stays the same. Older installed updaters can report success while leaving the old code in place. For Linux installs created by `install.sh`, refresh that updater once:

```bash
"$HOME/.local/share/awsherlock/venv/bin/python" -m pip install --upgrade --force-reinstall 'git+https://github.com/0gulcandogann/awsherlock.git@main'
```

The refreshed updater takes effect on the next invocation and displays real installer logs. `awsherlock --version` alone cannot distinguish code changes that share a version number.

To remove a Windows pipx install:

```powershell
py -m pipx uninstall awsherlock
```

For the default Linux/macOS script install, remove the `~/.local/bin/awsherlock` symlink and the `~/.local/share/awsherlock` directory. If you chose custom installation paths, remove those instead. Keep your cloned repository if you want to install again later.

## Troubleshooting

**`awsherlock` is not found.** On Windows, run `py -m pipx ensurepath` and restart the terminal application, including the IDE if you use its terminal. On Linux/macOS, check that your selected bin directory is on PATH. Use `Get-Command awsherlock` in PowerShell or `command -v awsherlock` in a Unix shell to check which command is being found.

**Credentials are missing or expired.** Check your selected profile and sign in again if it uses SSO. AWSherlock does not perform an interactive login. To confirm the source account with the AWS CLI, run `aws sts get-caller-identity --profile production`.

**The report says `AccessDenied`.** Review the specific operation in the collection issues, then compare your role permissions with [checks and permissions](#checks-and-permissions). Other checks can still produce findings, but denied checks have not been evaluated.

**A regional service could not be scanned.** Set a region through your profile,
`AWS_DEFAULT_REGION`, `--region` or `--regions`; review per-region coverage and
permissions. Only explicitly selected or configured regional scope is inspected.

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

Version 0.1.15 is published on PyPI and TestPyPI. It adds `scan --preview` for
an unverified local plan without AWS calls or output files, plus per-check
CloudTrail missing-fact explanations in coverage issues. No new AWS reads,
checks or report format were added in this version.

Version 0.1.10 adds opt-in NHI/AI identity governance, declarations/approvals,
bounded audit attribution across five connection branches, metadata-only native
AI role bindings and existing Access Analyzer evidence. The catalog has 35 checks
(29 default and six opt-in governance checks). It also includes explicit check,
account, OU and resource selectors, S3 account safeguard context, CloudTrail
management/source exclusions, scan-local collection measurements, successful
trail read reuse and safer partial collection. Measurements count SDK invocations
separately from HTTP retries; `--stats` remains elapsed/result counts. Synthetic
benchmarks do not establish live AWS performance. Collection remains read-only.

Version 0.1.5, dated 2026-09-16, adds explicit single/multiple-region selection,
per-region coverage in all reports, expected-account verification, per-request
timeouts and reusable snapshot saving during scans. IAM/S3 are collected once per
account; identical repeated findings are deduplicated. New offline discovery
commands explain checks and diagnose installation issues. Terminal output shares
one palette with color controls, compact summaries, stage diagnostics and measured
duration/count statistics. Existing 28 checks, SDK authentication, organization
scanning, offline evaluation and report formats remain supported. Collection stays
sequential; this release does not claim new security rules or measured API-call
performance improvements. Version 0.1.0 remains the original release baseline.

Recent changes simplify installation from a clone, add the convenience update command, organize terminal findings into severity-ordered cards, and give HTML reports a light theme with purple borders and orange shadows. Untrusted terminal control and directional formatting characters are shown as visible escapes in terminal results and CLI file messages. JSON and HTML retain the original data. Examples and development artifacts are excluded from the public tree and source distribution.

## License

[MIT](https://github.com/0gulcandogann/awsherlock/blob/main/LICENSE).
