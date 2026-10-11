# Output contracts in the current main source

This records current behavior for automation. Each artifact has its own version.
A plain scan selects seven services; eleven services are supported. Lead Delta
is an explicitly opt-in diff document extension, not a snapshot schema change.

## Exit statuses

| Status | `scan` | `diff` |
| --- | --- | --- |
| `0` | Completed selected scan, even if findings exist, unless `--fail-on` is met. | Completed comparison, even if changes exist, unless `--fail-on new` is met. |
| `1` | Incomplete coverage, denied/missing collection, unreadable input or output failure. Incomplete coverage takes precedence over `--fail-on`. | Missing/unreadable input or incomplete comparison with `--fail-on new`. |
| `2` | Invalid command-line option or value. | Invalid command-line option or value. |
| `3` | Complete scan has an unsuppressed finding at the requested `--fail-on high` or `critical` threshold. | `--fail-on new` found a new finding with sufficient coverage. |

Other commands may have command-specific outcomes. Ctrl+C in the guided or
update flow exits `130`. A zero exit status does not mean zero findings; inspect
the report and coverage. An `AccessDenied` or missing required fact never
counts as a passing security check.

## Machine-readable versions

`schema_version` is an **integer** in the artifacts below. The version applies
to each artifact, not to every output produced by AWSherlock.

| Artifact | Producer | Current top-level version | Notes |
| --- | --- | --- | --- |
| Snapshot | `snapshot` or `scan --save-snapshot` | `2` | New captures add normalized positive `relationships`; v1 remains readable. Strict reader validation; older snapshots remain readable with incomplete coverage for unsupported evidence. |
| Scan preview | `scan --preview --preview-format json` | `1` | `kind: scan-preview`; describes intended scope before collection. |
| Snapshot diff | `diff --output json` | `1` | `kind: snapshot-diff`; incomplete after-coverage can make a disappearance `UNKNOWN`. |
| Snapshot diff with Lead Delta | `diff --include-leads --output json` | `2` | Opt-in only; adds separate `lead_delta` object v1/policy v1. [Lead Delta contract](lead-delta.md). Finding thresholds and snapshot schemas are unchanged. |
| Finding history | `history --output json` | `1` | `kind: finding-history`. |
| Investigation leads | `leads --output json` | `2` | `kind: investigation-leads`; five existing patterns. Lead Delta does not change these rules or IDs. |
| Investigation Evidence Pack | `investigate --output json` | `1` | `kind: investigation-evidence-pack`; exact-one-Lead minimized offline export. COMPLETE export exits 0; PARTIAL export or fatal runtime error exits 1; usage errors exit 2. HTML requires `--report-file`. [Evidence Pack contract](investigation-evidence-pack.md). |
| Coverage Diagnostics | `coverage --output json` | `1` | `kind: coverage-diagnostics`; offline evidence-derived limitations and positive-observation context. COMPLETE is recorded evaluation status, never an account security PASS or inventory-completeness claim. |
| Identity view, `--view all` | `identities --output json` | `1` | `kind: identity-view`. |
| Filtered identity view | `identities --view ai\|unowned\|stale\|shared --output json` | `2` | Also includes view and match counts. |
| SDK measurements | `scan --measurements-file` | `1` | Counts SDK invocations, not HTTP attempts or retries. |
| Suppression input | `scan --suppressions-file` | `1` | Input document, not a report. |
| Identity declaration input | `scan --identity-inventory` | `1` | Input document, not a report; requires `--identity-governance`. |

The normal finding report JSON currently has `metadata`, `coverage`,
`findings` and `summary`, with optional `identities` and `suppressions`; it
has no top-level `schema_version`. SARIF export declares SARIF `2.1.0` in its
own format. Consumers should check the kind and version of the specific
artifact they read and handle unknown future versions explicitly.
