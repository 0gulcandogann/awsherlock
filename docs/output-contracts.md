# Output contracts in the current main source

This records current behavior for automation. It does not introduce a new
format or promise that every format has the same version number. A plain scan
selects seven services; RDS is an eighth supported, opt-in service.

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
| Snapshot | `snapshot` or `scan --save-snapshot` | `1` | Contains `metadata` and `services`; strict reader validation. Successful new RDS instance listings add an allowlisted `DescribeDBInstances` completion marker; older snapshots remain readable with incomplete new-check coverage. |
| Scan preview | `scan --preview --preview-format json` | `1` | `kind: scan-preview`; describes intended scope before collection. |
| Snapshot diff | `diff --output json` | `1` | `kind: snapshot-diff`; incomplete after-coverage can make a disappearance `UNKNOWN`. |
| Finding history | `history --output json` | `1` | `kind: finding-history`. |
| Investigation leads | `leads --output json` | `1` | `kind: investigation-leads`. |
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
