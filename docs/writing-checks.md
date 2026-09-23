# Writing a security check

Start with a narrow, testable risk statement and an agreed stable check ID.
Existing IDs are visible through `awsherlock --list-checks` and
`awsherlock --describe-check AWSH-S3-001`; do not reuse an ID for different
semantics. The current registered catalog lives in
[`scanner.py`](../src/awsherlock/scanner.py) and
[`catalog.py`](../src/awsherlock/catalog.py). New checks require an approved
scope change; this guide is not permission to extend v0.1 on its own.

The data path is: credential/session layer → `ScanContext` → collector →
normalized `Resource.data` fact → rule → `Finding` → console/JSON/HTML. A
collector uses the context's session, never a separate boto3 session or AWS
write operation. Normalize only the fields required for the check; avoid raw
policies, credentials, secret values and unbounded event data. Follow an
existing collector such as [`collectors/s3.py`](../src/awsherlock/collectors/s3.py).

Define and validate the fact's shape before it is saved. The snapshot's
allowlist is in [`snapshot.py`](../src/awsherlock/snapshot.py) (`FACTS`), with
validation in `fact_validation.py` and service-specific normalizers. A known
absent configuration may be represented as a present `null` fact; a failed or
denied read omits the fact and records a bounded collection issue. Never
replace an unreadable fact with a safe default. Paginated list APIs must
process all pages; a failure must remain visible without discarding valid facts
already obtained from other reads.

A rule in `src/awsherlock/rules/` reads only normalized facts and returns
`list[Finding]`. It returns an empty list for a secure or non-applicable
resource, but raises on required missing/invalid evidence so evaluation can
report incomplete coverage. See [`engine.py`](../src/awsherlock/engine.py) and
[`evaluation.py`](../src/awsherlock/evaluation.py). Findings use the shared
model in [`models.py`](../src/awsherlock/models.py), include a bounded evidence
map, and describe risk and remediation without claiming effective access from
configuration alone. Register the rule in the service's rule tuple and ensure
the catalog title, required fact, scope and README/check reference agree.

Before proposing the check, verify these synthetic cases locally:

1. Insecure fact produces the intended finding and stable ID.
2. Secure fact produces no finding with complete coverage.
3. `AccessDenied`, malformed response and absent snapshot fact are incomplete,
   not PASS; an unrelated valid fact can still be evaluated.
4. Pagination and partial collection do not hide resources or failures.
5. Saved snapshot replay yields the same findings/coverage without AWS calls.
6. Console, JSON and standalone HTML do not leak credentials, raw policies or
   unescaped terminal/HTML control text.

Project regression fixtures currently stay local rather than being committed.
Include the synthetic case and expected result in your PR description so a
maintainer can reproduce and run the local suite. Live AWS is optional and
must not be required for unit tests; potentially billable calls need owner
approval.
