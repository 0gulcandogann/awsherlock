# AWSherlock — Codex Instructions

You are working on **AWSherlock**, an open-source AWS security scanner.

Before making changes:

1. Read `SPEC.md`.
2. Read `NOW.md`.
3. Read the relevant existing code and tests.
4. Implement **only** the task in `NOW.md`.

## Core Rule

Do not expand scope.

If you notice an unrelated improvement or future feature:

- do not implement it
- do not refactor toward it unless required for the current task
- mention it briefly in your final summary if important
- if appropriate, add a short entry to `IDEAS.md`

## Architecture Rules

Keep these layers separate:

```text
Credential Provider
        |
        v
    ScanContext
        |
        v
     Collector
        |
        v
 Normalized Resource
        |
        v
    Rule Engine
        |
        v
      Finding
        |
   +----+----+
   |    |    |
   v    v    v
Console JSON HTML
```

### AWS sessions

Collectors must not create their own independent boto3 sessions.

AWS sessions and assumed-role sessions must be created by the authentication/session layer and passed through a scan context.

### Credentials

Never:

- persist AWS access keys
- log secret access keys
- log session tokens
- place credentials in reports
- create custom credential storage

Use the standard AWS SDK credential chain.

### Scanner behavior

AWSherlock is read-only by default.

Do not add AWS write operations unless a future specification explicitly requires them.

An `AccessDenied` or missing permission must never be interpreted as a PASS result.

### Findings

Use normalized finding models.

Do not allow individual checks to invent arbitrary output formats.

### Reports

Do not add a frontend framework.

The v0.1 HTML reporter is:

```text
Jinja2
vanilla HTML
vanilla CSS
vanilla JavaScript
```

It must remain standalone and work without an internet connection.

---

## Code Quality

Prefer:

- clear Python
- small functions
- explicit models
- type hints
- predictable error handling
- low dependency count
- deterministic tests

Avoid:

- unnecessary abstraction
- premature plugin systems
- huge base classes
- hidden global state
- broad exception swallowing
- speculative refactors

---

## Testing

Every security rule must eventually have at least:

```text
insecure fixture -> finding exists
secure fixture   -> no finding
```

For AWS integrations:

- do not require real AWS credentials in unit tests
- mock AWS API responses
- test AccessDenied behavior
- test pagination where relevant

When a task changes behavior:

1. add or update tests
2. run relevant tests
3. report the test command and result

---

## Scope Control

v0.1 intentionally excludes:

- SaaS
- web dashboard
- database service
- attack paths
- graph visualization
- AI remediation
- multi-cloud
- Kubernetes
- SCP analysis
- Security Hub integration
- SARIF
- compliance framework mapping

Do not implement these during v0.1 unless `SPEC.md` is explicitly changed by the project owner.

---

## Working Style

Treat `NOW.md` as the active contract.

A task is complete only when its `Done when` section is satisfied.

Do not begin the next roadmap task automatically.

At the end of work, provide:

```text
What changed
Tests run
Files changed
Known limitations
```

Keep the summary concise.

Do not rewrite unrelated files.
