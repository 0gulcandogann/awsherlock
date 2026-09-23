# Contributing to AWSherlock

Open a focused issue or pull request with the AWSherlock version, command,
affected check ID, expected result and a sanitized reproduction. Never attach
credentials, raw policy documents, unsanitized snapshots or reports. Describe
the user-visible behavior and its detection limits.

Use Python 3.11 or newer. In a clone, create a virtual environment and install
the package in editable mode:

```bash
python -m venv .venv
# Activate .venv for your shell, then:
python -m pip install -e .
awsherlock --help
awsherlock --list-checks
```

The scanner is read-only. Authentication owns AWS sessions, collectors receive
the scan context, rules consume normalized resources, and reporters consume
findings and coverage. Keep offline snapshot replay working and do not turn
`AccessDenied` or absent facts into a PASS. See [Writing a check](writing-checks.md)
for the exact code paths and verification cases.

The project's regression fixtures are currently maintained locally and are not
published in this repository. Contributors can still provide a minimal,
synthetic secure/insecure/denied case in the PR description for maintainer
verification. Do not include real account identifiers, secrets or raw events.
There is currently no PR scanner CI gate; a green release-publishing workflow
is not evidence that a code change passed scanner tests.
