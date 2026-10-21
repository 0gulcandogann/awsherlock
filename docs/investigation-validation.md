# Read-only investigation validation

v0.5.1 has synthetic offline regression and package validation. **No live AWS
validation was executed for this release preparation.** Credentials, production
accounts, resource provisioning and cloud costs were not used or authorized.
Historical pilot results in [pilot.md](pilot.md) do not validate this release.

## Local validation (no credentials)

From a checkout with the package, pytest, build and hatchling installed:

```bash
python -m pytest -q -m 'not browser'
python -m pytest -q -m browser
python -m compileall -q src scripts .github/scripts
python .github/scripts/ci_checks.py
python -m build --no-isolation --outdir dist/v0.5.1
python .github/scripts/release.py artifacts --dist dist/v0.5.1
```

Browser tests require a working Chromium/Chrome/Edge process. They load a local
file, block DNS and use no server or CDN. A sandbox launch failure is not a
passing or skipped browser check; run these in the dedicated Linux/Chrome CI job
or a permitted local environment. CI's main matrix runs all non-browser tests;
the browser job explicitly runs all browser-marked tests, including the graph.
There is no new runtime testing dependency.

Set `AWSHERLOCK_TEST_BROWSER` to an executable path or command when automatic
browser discovery selects the wrong installation. Set
`AWSHERLOCK_REQUIRE_BROWSER=1` to fail rather than skip when no browser exists;
Scanner CI sets this for its Chrome job. Launch failures include the exit code
and a bounded stderr excerpt; startup errors and timeouts fail explicitly.

The local release environment has `Seccomp: 2` / `NoNewPrivs: 1`. Direct Python
probes allow AF_UNIX socket pairs, including SOCK_SEQPACKET, but reject
`setsockopt(SOL_SOCKET, SO_PASSCRED, 1)` with EPERM. AF_INET socket creation is
separately denied. Chromium's version command succeeds, but headless startup
fails on crashpad socket configuration. See the precise probes and normal-terminal
commands in the [final readiness report](releases/v0.5.1-readiness.md).
This is an external IPC permission blocker, not a report rendering result.
It cannot be fixed here without unavailable execution permissions. Do not
disable or bypass the host security policy; rerun the browser suite in the
existing permitted CI/browser environment. No browser success is claimed.

Synthetic scenarios reuse all five Lead fixtures and include EC2/IMDS/public IP,
Lambda URL/role, governance/stale roles, Bedrock DRAFT and exact AgentCore runtime
versions. Additional tests cover denied/partial reads, policy restrictions,
unknown reachability, foreign/ambiguous identities, deterministic permutations,
v1/v2 replay, unchanged Lead Delta, XSS and bounded graph integrity.

Saved public fixtures in `tests/fixtures/contextual-ec2-v2.json` and
`contextual-ec2-partial-v2.json` describe synthetic, reserved-address resources;
they are not live account captures. `scripts/validate_investigations.py` accepts
any supported saved snapshot and optionally the report from that same collection:

```bash
python scripts/validate_investigations.py tests/fixtures/contextual-ec2-v2.json
python scripts/validate_investigations.py facts.json --report live.json
```

The helper validates replay fields and metadata scope, repeats investigation
generation to check reproducibility and prints only counts, completeness and a
SHA-256 digest. It never collects or authenticates. Exit 0 means validation ran
and any supplied capture matched; `incomplete: true` remains a limitation, not a
PASS. Exit 1 means invalid input, differing fields or non-deterministic output.
Only differing field names are printed, never private payloads. Capture/replay
comparison requires all checks/resources and the same saved identity declarations;
selected or suppressed live reports require corresponding evaluation options and
must not be compared to an unselected replay as if identical.

## Authorized live procedure (not executed)

Obtain explicit authorization for one existing test account, audit profile,
region, services and read operations before running these examples. Use existing
owner-provided fixture resources and roles. No command here provisions or mutates
AWS resources. Mark unavailable cases UNTESTED; do not create insecure fixtures.

1. Verify the expected account and record independently known configuration,
   profile alias, region, source commit, SDK versions and scope. Start with serial
   collection and bounded request timeouts/retries:

   ```bash
   export AWS_RETRY_MODE=standard
   export AWS_MAX_ATTEMPTS=3
   awsherlock scan --profile approved-test --expect-account 123456789012 --region eu-west-1 --services ec2,iam,lambda --timeout 10 --max-workers 1 --save-snapshot facts.json --output json --report-file live.json --no-progress
   ```

   The environment setting bounds SDK attempts per request, including the initial
   request; it is not a total scan deadline or API rate limit. AWSherlock adds no
   retry loop. SDK configuration remains inherited. See the official
   [Boto3 retry configuration](https://docs.aws.amazon.com/boto3/latest/guide/retries.html).
   In PowerShell use `$env:AWS_RETRY_MODE='standard'` and
   `$env:AWS_MAX_ATTEMPTS='3'`. Record the actual client configuration, rather than
   assuming worker count bounds API calls per second.
2. Replay this **same capture** offline, compare it and derive both reports:

   ```bash
   awsherlock scan facts.json --output json --report-file replay.json --no-progress
   python scripts/validate_investigations.py facts.json --report live.json
   awsherlock investigate facts.json --contextual --report-file investigations.json
   awsherlock scan facts.json --output html --report-file investigations.html --no-progress
   ```

   Record exit codes. Incomplete scans/exports may write useful artifacts and
   exit 1. Compare independent expected observations, not just live/replay
   agreement. Open the HTML with networking disabled; inspect node selection,
   coverage gaps, references, assumptions and the text fallback.
3. Exercise available cases in the ledger below using already-existing resources
   and separately authorized restricted roles. Use a different output directory
   per account/scope; never combine account evidence. Wrong `--expect-account`
   must stop before resource collection. IAM uses global region null.
4. Bedrock/AgentCore context is separately opt-in. An approved capture may add
   `--identity-governance --identity-ai-services --identity-ai-production` and
   `--services iam,ec2,lambda,bedrock`. Existing per-service and identity
   permissions in the README still apply. Bedrock DRAFT and AgentCore exact
   versions are distinct; endpoint live/target configuration does not prove
   invocation, production traffic or credential access.
5. Record observed results, mismatch explanations and remaining UNTESTED cases.
   Keep raw snapshots/reports private; use aliases and synthetic reproductions
   in shared issues. A future maintainer must approve release actions separately.

## Live evidence ledger

All rows start **NOT EXECUTED** for v0.5.1; replace a status only with retained,
authorized evidence. Synthetic tests are not live API/retry validation.

| Case | Independent verification and expected behavior | Status |
| --- | --- | --- |
| EC2 profile/role | Existing instance profile resolves to exact IAM role; public IP and IMDS settings are separate observations. Routes/NACLs/application path remain unknown. | NOT EXECUTED |
| Lambda role/URL | Exact function-role binding and authentication/policy configuration; resource policy/effective anonymous access unproven. | NOT EXECUTED |
| Bedrock / AgentCore | DRAFT agent or immutable runtime-version role, correct endpoint live/target version separation; no latest/traffic inference. | NOT EXECUTED |
| AccessDenied / partial pages | Existing restricted role and available pagination/API-failure case; useful positive facts retained, coverage incomplete, no false PASS or resolved disappearance. | NOT EXECUTED |
| Cross-account isolation / retries / replay | Expected-account mismatch blocks collection; each account isolated. Exhausted throttling stays incomplete under bounded retries; same-capture replay matches. Do not induce throttling with a load test. | NOT EXECUTED |
