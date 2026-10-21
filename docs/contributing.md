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
python -m pip install -e '.[dev]'
awsherlock --help
awsherlock --list-checks
```

Development tools are optional dependencies in `pyproject.toml`; ordinary package
installation keeps the existing runtime dependencies. The repository previously
installed test/build tools separately and had no dev extra or linter settings.
The dev extra now includes pinned Ruff/Black versions for repeatable checks.

```bash
python -m ruff check .
python -m black --check .
python -m compileall -q src scripts tests .github/scripts
```

To apply confirmed safe formatting changes, run
`python -m black .`, review the diff and rerun tests.
Ruff uses its core error/undefined-name/unused-name rules; Black owns formatting.
Both target Python 3.11 with a 100-column preference. No typing checker is
configured, so no mypy/pyright pass is implied by these checks. Do not suppress
checks or exclude existing source merely to make a release gate pass.

Shared pytest fixtures are registered explicitly in `tests/conftest.py` with
service-specific context names (`s3_context`, `iam_context`, and so on). Keep their
original function scope and provider module state; do not remove a fixture
registration as an unused import. Explicit `__all__` exports document those
registrations. The original fixture factory reference in `test_m5.py` is also
intentional.

The [readiness report](releases/v0.5.1-readiness.md) records the executed tool
versions, fixture-provider audit and sandbox-specific Black IPC limitation.

The scanner is read-only. Authentication owns AWS sessions, collectors receive
the scan context, rules consume normalized resources, and reporters consume
findings and coverage. Keep offline snapshot replay working and do not turn
`AccessDenied` or absent facts into a PASS. See [Writing a check](writing-checks.md)
for the exact code paths and verification cases.

The public regression suite and synthetic fixtures are in `tests/`; they are
excluded from package archives. Run `python -m pytest -q -m 'not browser'` and,
with a working Chromium/Chrome/Edge process, `python -m pytest -q -m browser`.
Scanner CI runs the non-browser matrix and a separate Linux/Chrome browser job.
Do not include real account identifiers, secrets or raw events in fixtures.
Read [architecture](architecture.md) and the
[investigation validation guide](investigation-validation.md) for evidence
semantics, graph limits and the independently authorized live procedure.
