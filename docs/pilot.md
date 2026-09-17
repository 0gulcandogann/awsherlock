# Real-AWS pilot

[README](../README.md) · [35-check matrix](validation-matrix.md)

This guide prepares a read-only pilot. No real AWS scan has been performed for
this documentation package. Resource provisioning, role/policy changes and
remediation are separate owner-managed work. Start with existing known resources
in one account and one explicit region; expand to multiple regions/accounts only
after recording that baseline. Estimates exclude AWS access and reader waiting.

1. Record installed version, source commit/build, profile/account alias, explicit
   regions, selected services and the independent expected facts for each selected
   matrix scenario. Use the SDK credential chain or existing SSO session. Review
   the matrix permission bundles; use an existing audit role. Record unavailable
   scenarios as UNTESTED rather than provisioning insecure resources implicitly.
2. Choose fresh output paths in a restricted directory. Run a single-region scan
   with same-collection snapshot capture and JSON output:

   ```bash
   awsherlock --version
   awsherlock scan --profile pilot --expect-account 123456789012 --region eu-central-1 --save-snapshot pilot-facts.json --output json --report-file pilot-live.json --stats --no-progress
   awsherlock scan pilot-facts.json --output json --report-file pilot-replay.json --no-progress
   awsherlock scan pilot-facts.json --output html --report-file pilot.html --no-progress
   ```

   Replace profile/account/region with the agreed scope. Read stderr and exit
   status even when a JSON file exists. Exit 1 is not equivalent to zero findings;
   examine coverage and issues. Exit 0 can include findings. Existing output paths
   are refused. Do not capture a separate snapshot after the scan as a substitute
   for the same collection: the environment could have changed.
3. Compare live/replay finding tuples (ID/account/region/resource/evidence),
   coverage, identities when present, and summary. Compare unordered collections
   by their identities; retain evidence differences. Record explainable metadata
   differences. Check independent AWS read-only configuration observations near
   collection time, not just agreement with another scanner. Complete the matrix
   ledger for each scenario and retain all 35 IDs, including those not attempted.
4. Exercise available secure/insecure pairs and missing-permission scenarios with
   existing owner-provided roles/resources. Avoid disabling safeguards merely to
   make a test pass. Clock-aged credentials and impossible encryption/runtime
   configurations may stay UNTESTED in real AWS; mocked coverage is labeled
   separately. Record duration, inspected resources, evaluated/not-scanned counts,
   denied operations and partial failures, without claiming live API-call counts.
5. Open pilot.html offline and ask a pilot reader to identify the affected
   resource, reason, verification evidence and next action. Record whether help
   was needed. Test search, sorting and account/service/severity filters; confirm
   collection gaps remain visible. Do not generate a general security score.

## Separate opt-in identity pilot

Use the documented [inventory schema](../README.md#identity-governance-and-ai-attribution).
Record the exact inventory revision and whether it claims completeness for the
target account. A partial/missing list cannot establish approval. Start with:

```bash
awsherlock scan --profile pilot --expect-account 123456789012 --region eu-central-1 --services iam --identity-governance --identity-inventory identities.json --save-snapshot identity-facts.json --output json --report-file identity-live.json --no-progress
awsherlock scan identity-facts.json --services iam --identity-governance --identity-inventory identities.json --output json --report-file identity-replay.json --no-progress
```

Add `--identity-events`, `--identity-ai-services` or `--identity-analyzers` only
for separately recorded evidence scenarios with their read permissions. Live
evidence switches are collection options; offline replay uses the saved facts
and the same inventory. Check external/same-account roles and chains, IAM users,
OIDC non-AI workloads, Lambda/EC2/native AI bindings, and shared/unknown actors.
Declarations and native bindings do not prove execution; missing history does
not prove non-use. Do not export raw audit events, credential IDs or secret values.

## Expand scope after the baseline

For `--regions` or `scan organization`, `--save-snapshot` creates a new directory
of account/scope files. Replay each file separately; the CLI does not replay a
directory as a combined report. Compare each replay with the corresponding scope
in the combined live report; account-wide IAM/S3 observations and deduplicated
findings must be accounted for rather than summing everything blindly.

```bash
awsherlock scan organization --profile pilot --regions eu-central-1,eu-west-1 --accounts 123456789012,234567890123 --save-snapshot org-facts --output json --report-file org-live.json --no-progress
```

Record source and member accounts separately. Verify per-account role failures,
regional denials, account filtering and optional descendant `--ous` selection.
OU/account selection controls which accounts are assumed; `--checks` and exact
`--resources` control evaluation and leave collection unchanged. Exclusions and
unmatched resources stay visible as incomplete/NOT_SCANNED coverage; tags are
not selectors. Other regional scope remains untested; IAM/S3 run once per account
and S3 discovers bucket regions independently of `--regions`.

Retain raw artifacts privately; use resource/account aliases in shared ledgers
and sanitized synthetic facts for public issues. Reports and snapshots contain
sensitive configuration despite excluding credentials. The pilot is complete
when attempted scenarios have evidence-backed outcomes, mismatches are explained
or assigned for correction, and all unattempted scenarios remain explicitly
untested. Later report improvements, comparisons and new services require their
own NOW.md contracts; this guide authorizes no release or next package.
