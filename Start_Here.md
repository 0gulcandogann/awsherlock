# AWSherlock — Start Here

You are working on **AWSherlock**, an open-source AWS security scanner.

Your job is to implement the project incrementally, safely, and strictly according to the current project specification.

Do not treat this repository as an open-ended coding task.

AWSherlock follows a fixed **20-working-day / 4-week v0.1 development plan**.

The active task for the current day is defined in `NOW.md`.

---

# 1. Before Doing Anything

Before modifying any file, read these files in this exact order:

1. `SPEC.md`
2. `AGENTS.md`
3. `NOW.md`
4. Relevant existing source files
5. Relevant existing tests

Understand the current architecture before writing code.

The most important rule is:

> Implement only the task defined in `NOW.md`.

Do not automatically begin future roadmap tasks.

Do not implement unrelated ideas.

Do not expand scope because something seems useful.

If something is not required by `NOW.md`, it is normally out of scope for the current task.

---

# 2. Project

**AWSherlock** is an open-source AWS security scanner.

It inspects AWS environments using read-only access, evaluates security configurations, and produces:

* terminal output
* structured JSON output
* standalone HTML security reports

AWSherlock is a CLI security tool.

It is not a SaaS platform.

It is not a web application.

It does not require a backend server.

The standalone HTML report must eventually be viewable directly in a browser without requiring internet access.

---

# 3. v0.1 Goal

The v0.1 release should eventually support workflows such as:

```bash
awsherlock scan

awsherlock scan --profile production

awsherlock scan \
  --role arn:aws:iam::123456789012:role/AWSherlockAuditRole

awsherlock scan --services iam,s3

awsherlock scan organization

awsherlock scan snapshot.json
```

Outputs:

```text
Console
JSON
Standalone HTML
```

Do not implement these features before their corresponding task appears in `NOW.md`.

---

# 4. Current Source of Truth

The following files have different responsibilities.

## `SPEC.md`

Defines:

* product architecture
* v0.1 scope
* supported services
* security model
* output requirements
* non-goals
* release definition

`SPEC.md` describes where the project is going.

---

## `AGENTS.md`

Defines:

* engineering rules
* Codex behavior
* architecture boundaries
* testing expectations
* credential handling rules
* scope-control rules

`AGENTS.md` describes how the project should be implemented.

---

## `NOW.md`

Defines the only task you should currently implement.

`NOW.md` is the active task contract.

If `NOW.md` says Day 3, do not implement Day 4.

If `NOW.md` requires only one feature, implement only that feature.

---

## `IDEAS.md`

Future ideas belong here.

Entries in `IDEAS.md` are not requirements.

Do not implement ideas from this file unless they are explicitly promoted into `SPEC.md` and `NOW.md`.

---

# 5. Scope Control

Scope control is extremely important in this repository.

Do not implement future features simply because:

* they are easy
* they are related
* they would improve the architecture
* they may be useful later
* they reduce future work
* they seem like a natural extension

If the current task does not require them, do not implement them.

If you discover an interesting future improvement:

1. Do not implement it.
2. Do not refactor unrelated code for it.
3. Add a short note to `IDEAS.md` only if it is genuinely useful.
4. Continue with the current task.

Avoid speculative architecture.

Avoid premature abstractions.

Prefer the simplest architecture that correctly satisfies the current task and the existing specification.

---

# 6. Core Architecture

AWSherlock should evolve toward this architecture:

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

Keep responsibilities separate.

---

# 7. Collectors

Collectors are responsible for collecting AWS facts.

Collectors should not decide how findings are displayed.

Collectors should not render HTML.

Collectors should not generate arbitrary output structures.

Collectors should eventually return normalized resource information for rules to evaluate.

Most importantly:

> Collectors must never create independent boto3 sessions.

The session/authentication layer owns AWS sessions.

Collectors receive the appropriate session or scan context.

This is required so the same collectors can work with:

* default credentials
* named profiles
* AWS IAM Identity Center / SSO
* temporary credentials
* STS AssumeRole
* cross-account scanning
* AWS Organizations

---

# 8. AWS Credentials and Authentication

AWSherlock must never build its own long-lived credential storage.

Never:

* save AWS access keys
* save AWS secret access keys
* save session tokens
* print secrets
* put secrets in exceptions
* put secrets in logs
* put credentials in reports
* commit credentials into fixtures

Use the standard AWS SDK credential chain.

Temporary credentials should be preferred where appropriate.

Future authentication flow:

```text
AWS Credential Chain
        |
        v
   Source Session
        |
        +----------------------+
        |                      |
        v                      v
Direct Scan              sts:AssumeRole
                               |
                               v
                        Temporary Session
                               |
                               v
                         Target Account
```

Do not implement authentication functionality before it is required by `NOW.md`.

---

# 9. Read-Only Security Principle

AWSherlock is a read-only security assessment tool by default.

Do not introduce AWS write operations unless a future specification explicitly requires them.

Examples of operations AWSherlock should normally avoid:

```text
Create*
Delete*
Put*
Update*
Modify*
Attach*
Detach*
Start*
Stop*
Terminate*
```

AWSherlock should inspect environments, not modify them.

---

# 10. Security-Sensitive Code Review

When the current task touches any of the following:

* AWS credentials
* STS
* AssumeRole
* IAM
* authorization
* permissions
* resource policies
* authentication
* secrets
* security rules
* security findings

perform an explicit security review before finishing.

Review at least:

```text
credential handling
IAM privilege scope
temporary credential usage
trust relationships
resource scoping
error handling
AccessDenied behavior
false positives
false negatives
pagination
regional vs global AWS services
unexpected API response shapes
missing resources
sensitive logging
```

Do not blindly trust successful API calls.

---

# 11. Permission Failures

This rule is critical.

> An inability to inspect a resource must never be interpreted as a secure result.

For example:

```text
AccessDenied
```

must not become:

```text
PASS
```

AWSherlock should eventually distinguish states such as:

```text
PASS
FAIL
ERROR
PARTIAL
NOT_SCANNED
ACCESS_DENIED
```

The exact implementation may evolve with the specification.

When permissions are missing, make the limitation visible.

Security scanners must not provide false confidence.

---

# 12. AWS API Edge Cases

When implementing AWS collectors, always consider whether the API requires:

## Pagination

Examples:

```text
NextToken
Marker
IsTruncated
ContinuationToken
```

Do not assume the first response contains all resources.

Use AWS paginators when appropriate.

---

## Regional vs Global Services

AWS services behave differently.

Examples:

```text
IAM              global
Organizations    global
S3               mixed/global behavior
EC2              regional
Lambda           regional
KMS              regional
CloudTrail       regional/multi-region behavior
```

Do not assume every collector follows the same regional model.

---

## Missing or Optional Fields

AWS API responses may omit fields.

Do not assume every optional dictionary key exists.

Avoid fragile indexing when `.get()` or explicit validation is more appropriate.

---

# 13. Findings

Security rules must eventually return normalized findings.

Individual checks should not invent their own output formats.

A finding should contain information such as:

```text
id
title
description
severity
service
account_id
region
resource_id
resource_arn
evidence
risk
remediation
references
```

Example IDs:

```text
AWSH-S3-001
AWSH-IAM-002
AWSH-EC2-004
AWSH-LAMBDA-001
```

Severity vocabulary:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

Use the model defined by the repository when one exists.

Do not create duplicate finding models.

---

# 14. Rule Quality

Every security rule should eventually be evaluated from two directions:

```text
insecure configuration -> finding exists

secure configuration   -> no finding
```

Also consider:

```text
missing data

AccessDenied

partial visibility

unexpected AWS response

multiple resources

pagination

regional variation
```

A security rule is not complete merely because it detects one intentionally vulnerable fixture.

False positives and false negatives matter.

---

# 15. Tests

Tests are required.

When behavior changes:

1. Add or update tests.
2. Run the relevant tests.
3. Fix failures caused by your change.
4. Report the commands executed.

AWS integration unit tests must not require real AWS credentials.

Prefer:

* mocked AWS responses
* deterministic fixtures
* isolated rule tests
* CLI tests
* explicit AccessDenied tests

Never require a live production AWS environment for normal unit testing.

---

# 16. Test Discipline

Do not finish a task without running relevant tests when tests exist.

At minimum, run targeted tests for the code you modified.

When practical, run the complete test suite before finishing.

Do not claim tests passed unless they were actually executed.

If something could not be tested, explicitly say so.

---

# 17. HTML Reporter Rules

The v0.1 HTML reporter will eventually use:

```text
Jinja2
Vanilla HTML
Vanilla CSS
Vanilla JavaScript
```

Do not introduce:

```text
React
Next.js
Vue
Angular
Svelte
frontend build pipelines
external CDN dependencies
```

unless the project specification is intentionally changed.

The report should eventually:

* be a single file
* open locally
* require no backend
* require no internet
* embed CSS
* embed JavaScript
* support filtering
* support search
* show security findings
* show scan metadata
* show coverage information

Do not implement the HTML reporter until `NOW.md` asks for it.

---

# 18. Dependencies

Keep dependencies minimal.

Before adding a dependency, ask:

1. Is this necessary for the current task?
2. Can the standard library reasonably do it?
3. Is the package mature and maintained?
4. Does it significantly increase complexity?
5. Does it create supply-chain risk?

Do not add dependencies for convenience alone.

---

# 19. Code Style

Prefer:

* clear Python
* small functions
* meaningful names
* explicit models
* type hints
* predictable control flow
* explicit errors
* simple architecture
* deterministic behavior

Avoid:

* giant functions
* unnecessary metaprogramming
* hidden global state
* premature plugin systems
* excessive inheritance
* broad base classes
* magic behavior
* speculative generalization
* deeply nested conditions
* swallowed exceptions

Readable security code is more valuable than clever security code.

---

# 20. Exception Handling

Do not use broad exception handling such as:

```python
try:
    ...
except Exception:
    pass
```

unless there is an extremely strong reason.

Never silently ignore:

* AWS API errors
* AccessDenied
* malformed responses
* unexpected scanner state

Handle known exceptions explicitly when practical.

If the scanner can continue safely, preserve enough information to report that the scan was incomplete.

---

# 21. Logging

Never log:

```text
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN
authorization headers
secret values
credentials
private keys
full sensitive environment variable values
```

Logs should be useful for debugging without leaking credentials.

When uncertain whether a value is sensitive, avoid logging it.

---

# 22. No Unrelated Refactors

Do not refactor unrelated files while completing a task.

If the current task touches:

```text
src/awsherlock/auth.py
```

do not randomly reorganize:

```text
reporters/
checks/
README
tests unrelated to auth
```

unless required to make the current task correct.

Small focused changes are preferred.

---

# 23. Avoid Premature Optimization

Do not optimize for hypothetical hundreds of AWS accounts unless the current task requires it.

Do not add:

```text
thread pools
async frameworks
multiprocessing
distributed queues
caching layers
databases
```

without a concrete current requirement.

Correctness and simplicity come first.

Performance optimization can happen after measurements exist.

---

# 24. v0.1 Explicit Non-Goals

Do not implement these features during v0.1 unless the specification is explicitly changed:

```text
SaaS platform
user accounts
login system
hosted dashboard
database server
React frontend
Next.js frontend
attack-path engine
graph visualization
SCP security analysis
Security Hub integration
SARIF
GitHub Actions scanning integration
CIS certification
PCI compliance mapping
SOC 2 compliance mapping
Bedrock scanning
AgentCore scanning
AI-generated remediation
multi-cloud scanning
Azure
GCP
Kubernetes
continuous monitoring daemon
automatic remediation
```

These may become future versions.

They are not current requirements.

---

# 25. Working Method

For every task:

## Step 1

Read:

```text
SPEC.md
AGENTS.md
NOW.md
```

---

## Step 2

Inspect the existing implementation.

Do not assume the repository still matches an earlier mental model.

---

## Step 3

Restate internally what the current task actually requires.

Identify the smallest correct implementation.

---

## Step 4

Implement only that task.

---

## Step 5

Add/update tests.

---

## Step 6

Run relevant tests.

---

## Step 7

Review the diff for:

```text
scope creep
security issues
unnecessary dependencies
credential leakage
unrelated refactors
dead code
missing tests
```

---

## Step 8

Stop.

Do not begin tomorrow's task.

---

# 26. Current Task Authority

`NOW.md` has priority over assumptions about what should happen next.

If the roadmap suggests IAM scanning but `NOW.md` says implement S3 only:

Implement S3 only.

If `NOW.md` says bootstrap the CLI:

Do not implement boto3.

If `NOW.md` says implement AssumeRole:

Do not implement Organizations unless required for the AssumeRole task.

---

# 27. Definition of Done

A task is not done merely because code was written.

The `Done when` section of `NOW.md` is the acceptance criteria.

Check every item.

If one item is not satisfied, the task is not complete.

---

# 28. End-of-Task Response

When finished, provide a concise report with exactly these sections:

```text
What changed

Tests run

Files changed

Known limitations
```

Example:

```text
What changed
- Added the initial Typer CLI.
- Added --version support.
- Added the placeholder scan command.

Tests run
- pytest tests/test_cli.py
- 3 passed

Files changed
- src/awsherlock/cli.py
- src/awsherlock/__init__.py
- tests/test_cli.py

Known limitations
- AWS scanning is intentionally not implemented yet.
```

Do not provide a large roadmap discussion unless specifically requested.

Do not begin the next task.

---

# 29. If You Find a Bug Outside the Current Task

If you discover a severe issue that blocks the current task:

Fix the minimum necessary issue.

If the unrelated issue does not block the task:

Do not fix it.

Mention it under:

```text
Known limitations
```

or add it to `IDEAS.md` / an appropriate backlog file if useful.

---

# 30. If Requirements Are Ambiguous

First use:

```text
SPEC.md
AGENTS.md
existing architecture
existing tests
```

to resolve the ambiguity.

Prefer the smallest implementation consistent with those sources.

Do not invent large features to solve minor ambiguity.

If multiple implementations are reasonable, prefer:

```text
simpler
safer
more testable
less coupled
less privilege
fewer dependencies
```

---

# 31. Security Scanner Mindset

Remember that AWSherlock is security software.

Incorrectly reporting a vulnerability is undesirable.

Incorrectly claiming a resource is secure when it could not be inspected is worse.

Prioritize:

```text
correctness
visibility
evidence
safe failure
clear uncertainty
```

over:

```text
pretty output
feature count
complex abstractions
speed
```

Every finding should eventually be defensible from collected evidence.

---

# 32. Project Philosophy

AWSherlock should remain:

```text
small enough to understand
modular enough to extend
safe enough to trust
useful enough to run
simple enough to finish
```

The goal is not to build every possible AWS security feature in v0.1.

The goal is to release a high-quality open-source AWS security scanner after 20 focused working days.

---

# 33. Start the Current Task

Now:

1. Read `SPEC.md`.
2. Read `AGENTS.md`.
3. Read `NOW.md`.
4. Inspect relevant source code and tests.
5. Implement only the current task.
6. Add or update tests.
7. Run relevant tests.
8. Review for security and scope creep.
9. Stop after satisfying the current task.

Do not begin the next day's work automatically.

# Development Roadmap

Read `ROADMAP.md` before starting work.

Determine the current day from the project's completed work.

Work only on that day's section.

After completing the current day, stop and ask the project owner for explicit permission before beginning the next day.

Never automatically advance to the next day.