# Contributing

Open an issue for a bug or a focused proposal. Include the AWSherlock version,
command, affected check ID, expected result, and a sanitized reproduction.
Never attach AWS credentials or an unsanitized snapshot or report.

For code changes, use Python 3.11 or newer in a virtual environment:

```bash
python -m venv .venv
```

Activate it with `source .venv/bin/activate` on Linux/macOS or
`.\.venv\Scripts\Activate.ps1` in PowerShell, then install:

```bash
python -m pip install -e .
awsherlock --help
```

Keep AWS sessions in the authentication layer, collection in collectors,
evaluation in rules, and rendering in reporters. Reports must work offline.
Do not add AWS write calls, custom credential storage, or secret-value retrieval.

Describe how you verified the change. For a security check, cover both secure and
insecure configurations and include missing-permission behavior. For collectors,
check pagination and partial failures. Use synthetic data when reproducing issues.

Keep pull requests focused. Explain the user-visible change and its limits, and
check that your diff contains no credentials, local reports, or unrelated files.
