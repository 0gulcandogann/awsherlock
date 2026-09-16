# Contributing

Use issues for bug reports and focused proposals. Include the version, command,
check ID, expected behavior and a sanitized reproduction. Use Python 3.11 or newer.

```bash
python -m venv .venv
# Activate your environment, then:
python -m pip install -e .
awsherlock --help
awsherlock scan examples/demo-snapshot.json --output json
```

The demo deliberately exits with code 1 for incomplete coverage. The maintainer's
local regression suite is not included in this public distribution. Include a
minimal synthetic reproduction with your proposal and describe its validation.
Cover secure/insecure configurations, pagination and AccessDenied where relevant.
Preserve independent facts when collection partially fails; missing permissions
must never become a PASS.

Keep sessions in the authentication layer, facts in collectors, evaluation in
rules and formatting in reporters. HTML must work offline without a framework.
Do not add AWS write calls, credential storage or secret-value retrieval.

Before a pull request, validate the affected behavior, inspect the diff for
secrets and unrelated changes, and explain the resulting behavior and validation.
Use synthetic account IDs and credentials in tests. Never attach a real snapshot
without sanitizing account/resource names and sensitive metadata.

Packaging verification:

```bash
python -m pip install build
python -m build
docker build -t awsherlock:local .
docker run --rm --network none awsherlock:local --version
```
