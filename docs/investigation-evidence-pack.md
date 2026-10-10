# Investigation Evidence Pack

Export minimized evidence for exactly one existing Investigation Lead from a
saved snapshot. This command is fully offline: it evaluates the validated
snapshot once and correlates once using that exact report. It does not collect
new evidence, create AWS clients, change Lead rules or prove an attack path.

## Commands and exits

Obtain the full ID with `awsherlock leads snapshot.json --output json`, then:

```text
awsherlock investigate snapshot.json --lead-id PATTERN:FULL_SHA256 --output json
awsherlock investigate snapshot.json --lead-id PATTERN:FULL_SHA256 --output json --report-file investigation.json
awsherlock investigate snapshot.json --lead-id PATTERN:FULL_SHA256 --output html --report-file investigation.html
```

`PATTERN:FULL_SHA256` is a placeholder: use the complete, exact, case-sensitive
Lead ID, not a prefix. JSON is the default and may go to stdout. HTML requires
`--report-file`. An existing destination is never overwritten, including the
input snapshot or an alias resolving to it. Files are created exclusively.

| Exit | Meaning |
| --- | --- |
| `0` | The selected positive Lead and its supporting evidence were exported with no detected supporting-evidence gaps. This is not a security PASS. |
| `1` | A clearly labeled `PARTIAL` artifact was exported, **or** a fatal input, selection, reference or output error occurred. Fatal validation/selection/reference errors write no artifact; inspect stderr and the artifact's `status` to distinguish outcomes. |
| `2` | Invalid command usage, such as missing snapshot/ID, unsupported output, or HTML without a report file. |

There is no Lead-based severity or failure threshold. Existing diff contracts
and Finding-only `--fail-on new` are unchanged.

## JSON contract v1

The standalone artifact has `kind: investigation-evidence-pack`, integer
`schema_version: 1`, and `export_policy_version: 1`. It is not a snapshot.

- `status`: `COMPLETE` or `PARTIAL`; `status_scope` explicitly limits this to
  supporting-evidence export, never security assurance.
- `lead`: existing ID, pattern, priority, title, exact subjects and related
  resources, and the existing conservative explanation.
- `findings`: selected supporting check IDs, titles, Finding severities, exact
  resource identities, allowlisted normalized evidence, references and source
  scan/check provenance. No persisted Finding API operation exists; its value
  is `null`, not a fabricated API name.
- `relationships`: only selected supporting positive edges with exact endpoints
  and their stored evidence. Missing operation provenance remains `null`.
- `source_snapshot`: scan ID, account, region, schema version, collection start,
  producer version and relationship capability. These describe the saved source,
  not AWS attestation or current infrastructure.
- `evaluation`: current evaluator/correlation version, M1 locator policy
  version, exact supporting check IDs and explanation source.
- `statements`: existing Lead `observed`, `unknown` and `not_proven` statements
  with their stable codes. Explanations remain derived, not new AWS observations.
- `coverage`: relevant **service-level** coverage and bounded issues (resource
  ID, stored operation and classified reason). Service completeness does not
  prove that every optional relationship API family was collected. IAM retains
  global `region: null`; regional coverage uses the source report region.
- `limitations`, `manual_steps`, `disclaimer`: evidence gaps, the existing rule's
  manual next step, and an explicit minimized-not-anonymous warning.

JSON object keys, Findings, Relationships, evidence sets, references and
limitations have canonical ordering. JSON and HTML contain no export-time clock,
random identifier or scheduling metadata. Identical validated input and exporter
version produce identical bytes. Snapshot v1/v2 formats remain unchanged.

## Identity and fatal errors

References resolve within this snapshot using account, region, service, resource
type, resource ID and validated ARN. Conflicting/ambiguous locators fail safely;
IAM group Findings cannot become role evidence. IAM role paths and partitions
are preserved. Every Lambda URL configuration must belong to the selected
function's partition/account/region/name; legitimate qualifiers are permitted.
Selected relationships must connect the selected subject in the pattern's
required direction and resolve to stored supporting evidence.

AgentCore `runtime-version` subjects may be relationship-only with no collected
Resource and no version ARN. Their real logical ID/version is retained without
fabricating an ARN. Other references require the current locator policy's
validated evidence; unsupported or inconsistent identity is not guessed.

Selection errors include `FULL_EXACT_LEAD_ID_REQUIRED`, `LEAD_NOT_FOUND`,
`AMBIGUOUS_LEAD_ID` and `INCONSISTENT_LEAD_IDENTITY`. Required support errors include
`REQUIRED_FINDING_UNAVAILABLE`, `REQUIRED_RELATIONSHIP_UNAVAILABLE`,
`INCONSISTENT_SUPPORTING_RELATIONSHIP`, `SUPPORTING_FINDING_UNAVAILABLE`,
`SUPPORTING_RELATIONSHIP_UNAVAILABLE`, `SUPPORTING_EVIDENCE_INVALID` and
`UNSUPPORTED_SUPPORTING_CHECK`. Locator errors reuse M1's stable codes, including
`AMBIGUOUS_RESOURCE_IDENTITY`, `CONFLICTING_RESOURCE_ARN`,
`LAMBDA_URL_IDENTITY_MISMATCH` and `EXECUTION_ROLE_BINDING_CONFLICT`.
`SOURCE_EVIDENCE_INVALID` denotes an invalid source during evaluation.

## Minimization and partial evidence

Only the selected Lead's checks are projected: Function URL ARN/auth, broad
Lambda role-policy identifiers, EC2 metadata/public-address indicators, IAM
attached-policy identifiers or normalized permission statements, owner/service-
linked flags, and stale-use ages/status/threshold. Normalized policy statements
contain only effect, condition-presence, action/resource lists and negative-
selector flags; they are not full IAM policy documents or effective permissions.

No raw Resource facts, policy documents, environments, prompts, application
content, tags, collector error messages, raw SDK responses, unrelated Findings,
Leads or relationship inventories are exported. Source validation still rejects
secret-bearing input. Necessary names, account IDs and ARNs remain visible:
**minimized does not mean anonymous**. Review those identifiers before sharing.

Stored operation labels must match explicit, case-sensitive export allowlists
in `investigation.py`, never an identifier pattern or a Get/List/Describe prefix.
Coverage uses the actual collector service's API and internal diagnostic labels
plus registered evaluation diagnostics. Compound IAM `IdentityBindings` labels
are enumerated for the four existing workload families and relevant saved regions.
Relationship operations are validated against evidence service/fact and workload
service: `iam/identity_bindings` or `bedrock/execution_role_arn`. This preserves
legitimate lowercase/dotted EC2 labels and fixed Lambda runtime diagnostics.
Unknown or context-inconsistent operations become `null`, with
`PROVENANCE_FIELD_UNAVAILABLE` and PARTIAL status; other positive support remains
available. Intentional historical `operation: null` stays null without adding
this gap. No API operation is fabricated to replace an unavailable value.

Positive mandatory support must remain available. Missing optional provenance,
incomplete IAM policy enrichment, relevant incomplete service coverage or v1's
unsupported relationships remain explicit limitations; detected supporting gaps
produce `PARTIAL`. A v1 finding-only Lead can therefore be exported, but does not
gain relationship completeness. Unrelated service failures do not make this
pack partial. Whole relevant-service coverage is conservative rather than a
new per-check completeness model.

All packs disclose unavailable API provenance, unassessed effective permissions,
non-exhaustive relationships and unavailable IAM incarnation continuity. Even
`COMPLETE` cannot establish compromise, reachability, successful invocation,
production traffic, remediation or a confirmed attack path. Historical snapshots
cannot establish current AWS state.

## Standalone HTML

HTML is a single static document with inline screen/print styles, semantic
headings, Jinja2 autoescaping and StrictUndefined. No JavaScript, external
assets, fonts, telemetry or network requests are needed. Only strictly validated
HTTPS references become links, with `noopener noreferrer` and no-referrer
attributes; unsafe references remain escaped text. There is no graph or inferred
attack-chain visualization.
