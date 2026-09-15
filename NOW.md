# AWSherlock — Current Task

## Current progress

- Completed day: Day 1 — CLI bootstrap; local installation verified and 4 tests passed.
- Current day: Day 2 — AWS Session and Scan Context (completed).
- Today's work: centralized boto3 sessions, named profiles, STS GetCallerIdentity,
  and ScanContext, as defined in `ROADMAP.md` Day 2.
- Next day: Day 3 — STS AssumeRole. Explicit owner approval is required to start.

## Day 2 scope and acceptance criteria

Support `awsherlock scan` and `awsherlock scan --profile production` using the
standard SDK credential chain. Create an in-memory ScanContext containing
account_id, caller_arn, partition, profile, region, and the centralized session.
Show identity metadata and state clearly that security checks are not implemented.

- [x] Default and named profile session paths work in mocked tests.
- [x] ScanContext preserves the shared session and resolves account identity.
- [x] Credential errors, AccessDenied, and malformed responses fail visibly.
- [x] AWSherlock does not persist or print credentials.
- [x] Tests pass without real AWS credentials or network access.
- [x] README matches the CLI; security and scope review completed.

## Verification and resume point

- `.\.venv\Scripts\python.exe -m pytest` — 45 passed in 0.57s.
- Editable installation with `.[dev]` succeeded; `pip check` passed.
- Installed `--help`, `--version`, and `scan --help` commands passed.
- Security review: session construction is centralized; no credential copying,
  storage, or logging; raw SDK errors are suppressed; AccessDenied fails with
  exit code 1; malformed/mismatched account identities are rejected. Partition
  parsing covers commercial, China, and GovCloud examples. GetCallerIdentity
  needs no pagination; no resource collection or write APIs were introduced.
- Live AWS credentials were not used; session behavior was tested with mocks.
- No unfinished Day 2 work remains. Resume with Day 3 (STS AssumeRole) after
  explicit approval, first replacing the active scope with ROADMAP.md Day 3.

AssumeRole CLI support, Organizations, collectors, checks, reports, Docker, and CI
are out of scope for Day 2. The Day 1 task below is historical only.

### Daily tracking

At every day transition, update this file with the current day, today's scope,
acceptance criteria, completion status, test results, and the next day number.
Only mark a day complete after its acceptance criteria have been verified.

---

## Day 1 — completed (historical task)

Bootstrap the project and create the first working CLI entry point.

### Goal

After installation in a development environment, these commands must work:

```bash
awsherlock --help
awsherlock --version
```

No AWS API calls are required today.

---

## Requirements

Create the minimum Python package required for the CLI.

Use:

- Python 3.11+
- Typer
- Rich

Recommended package layout:

```text
src/
└── awsherlock/
    ├── __init__.py
    ├── __main__.py
    └── cli.py
```

The project owner may adjust the repository layout if needed.

### CLI

`awsherlock --help` should expose the project name and a short description.

Include a placeholder `scan` command, but do not implement AWS scanning yet.

Expected shape:

```text
awsherlock --help
awsherlock --version
awsherlock scan --help
```

The `scan` command may print a clear placeholder message indicating that scanning is not implemented yet.

### Version

Initial version:

```text
0.1.0-dev
```

Keep the version in one obvious source of truth.

### Tests

Add basic CLI tests covering:

- `--help`
- `--version`
- `scan --help`

Do not require AWS credentials.

---

## Done when

Day 1 is complete when all of the following are true:

- [x] package installs locally
- [x] `awsherlock --help` works
- [x] `awsherlock --version` works
- [x] `awsherlock scan --help` works
- [x] basic CLI tests pass
- [x] no AWS API call occurs
- [x] no unrelated v0.1 features are implemented
- [x] README quick-start matches the actual CLI

---

## Do Not Do Today

Do not implement:

- boto3 sessions
- AWS profile authentication
- AssumeRole
- Organizations
- collectors
- security checks
- findings engine
- HTML reporting
- JSON reporting
- Docker
- CI
- attack paths

Those belong to later days.

---

## Suggested Codex Prompt

```text
Read SPEC.md, AGENTS.md, and NOW.md.

Implement only the Day 1 task from NOW.md.

Keep the change minimal.
Do not implement future AWS scanning features.
Add the required CLI tests.
Run the relevant tests when finished.

At the end, summarize:
- what changed
- tests run
- files changed
- known limitations
```
