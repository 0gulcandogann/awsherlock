# Evidence-aware Lead Delta (opt-in)

`awsherlock diff before.json after.json --include-leads --output json`

This is an offline observation comparison, not a remediation or attack-path
assessment. Each snapshot is validated and evaluated independently, then its
existing five Lead rules run against **only its own** Findings and Relationships.
Different scan IDs are expected; evidence is never combined across scans.

Without `--include-leads`, diff JSON remains document v1, console output and
Finding thresholds are unchanged. With it, diff JSON is document v2: all existing
Finding fields remain, with a separate `lead_delta` object. Snapshots remain v1/v2.
No AWS sessions, clients, permissions or new checks are needed.

## State policy 1

Only identities positively observed on at least one side receive a row.

| State | Requirement |
| --- | --- |
| `NEW` | Later positive Lead and earlier validated false required predicate. |
| `STILL_OBSERVED` | Positive Lead on both sides without confirmed security-support change. |
| `EVIDENCE_CHANGED` | Positive Lead on both sides with comparable, demonstrably changed normalized security support. |
| `NO_LONGER_OBSERVED` | Earlier positive Lead and later validated false required predicate. This does not prove remediation. |
| `UNKNOWN` | One-sided observations without a false witness; or scope/identity conflict. |

Per-side predicate assessments are `OBSERVED`, `NOT_OBSERVED_WITH_EVIDENCE`, or
`UNKNOWN`. A known false predicate can falsify a conjunction independently of
missing evidence for another predicate. Relationship-required patterns are
incomparable with snapshot v1 even if local negative facts exist.

`support_comparison` concerns security support: `EQUAL`, `CHANGED`, or `UNKNOWN`.
Confirmed change always selects `EVIDENCE_CHANGED`. Two positive observations
with incomplete support remain `STILL_OBSERVED` with `UNKNOWN` support. Uncertain
support does not invalidate independently positive observations.

`provenance_comparison` is separate. Changed operation/fact/service provenance
on the same positive edge does not change the security predicate: it permits
`STILL_OBSERVED` / security support `EQUAL` / provenance `CHANGED`. The actual
before/after relationship provenance remains in the export.

## Five existing predicate requirements

All joins use exact account, region, service, resource type, resource ID and
compatible non-null ARNs. IAM roles must have global region `null`. A broad IAM
predicate means any of `AWSH-IAM-001`, `002`, `003` on the exact role.

| Pattern | Positive requirements | Permitted negative witness |
| --- | --- | --- |
| `LAMBDA-URL-BROAD-ROLE` | Exact function: `LAMBDA-001` AND `002`. `RUNS_AS` is optional context. | Registered evaluator returns no Finding for validated `urls` or `role_policies`. |
| `PUBLIC-EC2-IMDSV1-BROAD-ROLE` | Exact instance: `EC2-004` AND `005`, positive `RUNS_AS` to an exact IAM role with a broad Finding. | Validated `metadata` falsifies `EC2-004` or `addresses` falsifies `005`. Missing instance-profile/role edges never falsify the Lead. Policy absence alone cannot prove the workload has no broad role. |
| `UNOWNED-BROAD-IAM-WORKLOAD-ROLE` | Exact role: `IAM-007` AND broad Finding AND incoming workload `RUNS_AS`. | Validated owner/profile plus approval declarations falsify `007`, or all three broad evaluators return no Finding with complete policy context. |
| `STALE-BROAD-IAM-ROLE` | Exact role: `IAM-009` AND broad Finding. | Recorded usage falsifies `009`, or complete policy facts falsify all three broad checks. Unknown/no-record tracking cannot establish a negative usage witness. |
| `AI-WORKLOAD-BROAD-EXECUTION-ROLE` | Bedrock agent or exact AgentCore runtime-version positive `RUNS_AS` to global IAM role with a broad Finding. | Authoritative, unambiguous exact role binding plus complete role policy facts falsify all three broad checks. Bedrock requires the collected execution-role fact and consistent positive edge; AgentCore requires a validated version-specific identity binding. No latest-version or production-traffic assumptions. |

Negative witnesses require a unique collected resource, a validated locator,
the check's required facts, and successful registered evaluation. A matching
raw collection issue (including service-wide pagination failure) blocks the
witness. IAM broad negatives additionally require `identity_policy_context.complete`
and both attached and normalized statement evidence. Governance requires an
explicit identity request, non-service-linked profile and relevant declarations;
unknown approval declarations cannot establish an owner-negative witness;
usage requires `recorded` tracking. Evaluators are reused, not copied.

Missing resources never imply disappearance. Empty relationship arrays never
prove absent bindings. Service `COMPLETE` is not relationship-family completeness.
No missing permissions or missing optional enrichment becomes a security PASS.

## Identity and support

Existing Lead IDs remain SHA-256 of pattern ID and canonical logical subjects;
scan IDs, ARNs and support do not enter their identity. IAM role paths remain
validated locators: conflicting non-null ARNs block confident matching. Scope
mismatch preserves diff's existing behavior (Finding UNKNOWN where applicable)
and makes Lead rows UNKNOWN; history's stricter error contract is untouched.

Each snapshot resolves Finding ARNs independently to one exact logical resource,
including its type. An ARN shared by distinct resources/types is ambiguous and
forces affected comparisons to UNKNOWN (`AMBIGUOUS_RESOURCE_IDENTITY`). Lambda
URL configuration ARNs must match the function's partition, account, region and
name; valid function qualifiers are permitted. Foreign or inconsistent URL
locators force UNKNOWN (`LAMBDA_URL_IDENTITY_MISMATCH`) for both negative
witnesses and positive support, never a confirmed evidence change.

Security support explicitly projects Finding references and normalized evidence,
relationship endpoint identities/types, related-resource identities and existing
observed statement codes. It never relies on dataclass equality (`compare=False`
fields exist). Lists in these five patterns' Finding evidence are treated as
sets; ordering/duplicates, prose, timestamps and scan IDs are not security changes.
Finding severity and Lead priority remain separate display concepts.

Matching complete Finding evidence can establish a change. Added/removed Finding
support requires a validated false witness on the opposite side. Changing optional
relationship membership is conservatively incomparable without an exhaustive
binding contract; membership difference alone never claims a security change.
An AI workload's exact authoritative role binding on each side can independently
prove `EXECUTION_ROLE_CHANGED`; both sides must have consistent positive edges
and comparable support. This is changed configuration evidence, not production
traffic or effective-access proof.
Incomplete policy context or supporting coverage prevents `EQUAL` and confirmed
Finding evidence comparison. v1 finding-only Leads still work, but their full
support comparison is UNKNOWN because relationships are unsupported.
Contradictory execution-role facts/bindings or multiple authoritative AgentCore
roles for one version force state UNKNOWN, even if an existing rule emits a
positive Lead. A merely missing optional binding makes support UNKNOWN instead.

## Document shape and reason codes

Diff v2 adds `lead_delta` (object version `1`, `comparison_policy_version: 1`):

- `before`, `after`: independent scan/account/region/time/producer provenance,
  snapshot schema version and relationship capability.
- `summary`: counts by Lead state, separate from top-level Finding counts.
- `observed_counts`: independent before/after positive Lead counts.
- `changes`: sorted by stable Lead ID; pattern, priority, exact subjects, state,
  per-side assessment/scan ID/false witnesses, support/provenance comparisons,
  `evidence_changes`, reason codes, per-side gaps and narrowly supporting evidence.
- False witnesses export only their required normalized facts and relevant IAM
  governance/policy-context gates, taken from that side's exact resource.
- Each exported support includes the existing Lead document, normalized supporting
  Finding evidence, and positive relationship evidence. It does not dump resources,
  unrelated Findings, credentials, policy documents or the whole snapshot.

Reason codes are deterministic machine-readable diagnostics:

- `REQUIRED_PREDICATE_FALSE`, `POSITIVE_OBSERVATIONS_ON_BOTH_SIDES`,
  `SECURITY_SUPPORT_CHANGED`, `RELATIONSHIP_PROVENANCE_CHANGED`.
- `SCOPE_MISMATCH`, `RESOURCE_SCOPE_MISMATCH`, `ROLE_SCOPE_MISMATCH`,
  `CONFLICTING_RESOURCE_ARN`, `AMBIGUOUS_RESOURCE_IDENTITY`, `IDENTITY_UNCERTAIN`,
  `UNVALIDATED_RESOURCE_LOCATOR`, `RESOURCE_NOT_OBSERVED`,
  `LAMBDA_URL_IDENTITY_MISMATCH`.
- `REQUIRED_FACT_UNAVAILABLE`, `COLLECTION_INCOMPLETE`,
  `IAM_POLICY_CONTEXT_INCOMPLETE`, `GOVERNANCE_EVIDENCE_UNAVAILABLE`,
  `OWNER_DECLARATION_INCOMPLETE`, `USAGE_TRACKING_UNCERTAIN`,
  `PREDICATE_EVALUATION_UNAVAILABLE`, `PREDICATE_NOT_ESTABLISHED`.
- `RELATIONSHIPS_UNSUPPORTED`, `RELATIONSHIP_COMPLETENESS_UNAVAILABLE`,
  `EXECUTION_ROLE_BINDING_UNAVAILABLE`, `EXECUTION_ROLE_BINDING_CONFLICT`,
  `SUPPORTING_FINDING_UNAVAILABLE`, `SUPPORTING_RELATIONSHIP_UNAVAILABLE`,
  `SUPPORT_COVERAGE_INCOMPLETE`, `SUPPORT_MEMBERSHIP_INCOMPARABLE`.

`--output console` adds a separate Lead summary and rows. No new output-file
option or overwrite behavior is introduced. `--fail-on new` remains Finding-only:
Lead NEW/UNKNOWN states cannot independently trigger exit 3/1. Existing incomplete
Finding coverage and scope rules still apply.

## Limitations

IAM unique incarnation IDs are not in historical snapshots: deleting and
recreating the same role/path cannot be distinguished. Matching logical identity
does not prove incarnation continuity. Old snapshots lack optional-family
completion markers; some comparisons deliberately remain UNKNOWN. No resource
deletion, effective-permission simulation, remediation, production traffic,
deployment-version selection or continuity outside supplied observations is proven.
