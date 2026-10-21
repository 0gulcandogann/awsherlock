# Contextual investigations (v0.5.1)

This derived engine turns all five existing Lead patterns into explainable
investigations. It creates no Findings or Leads, changes no severity, and uses
no network, credentials, clock, randomness, LLM or telemetry. Results describe
the saved collection observation, not the account's current state.

## Workflow

Use a profile/account/region you are authorized to assess. Existing scan syntax
is preserved; the following live command is an example, not an executed pilot:

```bash
awsherlock scan --profile audit --expect-account 123456789012 --region eu-west-1 --services ec2,iam,lambda --save-snapshot facts.json --output json --report-file findings.json --no-progress
awsherlock investigate facts.json --contextual --output json --report-file investigations.json
awsherlock investigate facts.json --contextual --output html --report-file investigations.html
awsherlock scan facts.json --output html --report-file report.html --no-progress
awsherlock coverage facts.json --output json
```

The second through fifth commands are offline. Open `investigations.html` or
`report.html` locally. Inspect `priority`, `priority_factors` and
`priority_explanation` in contextual JSON, then `observed`, `inferred`, `unknown`
and `coverage_gaps`. Neither an empty list nor exit 0 establishes account safety.
An existing output path is always refused.

`investigate --contextual --lead-id PATTERN:FULL_SHA256` selects one exact Lead
from the contextual result. Obtain IDs with `leads facts.json --output json`.
Without `--contextual`, `--lead-id` remains required and the original minimized
Evidence Pack v1 is produced unchanged. It contains allowlisted supporting
payloads; contextual output contains references, avoiding duplicate payloads.

Exit 0 means a derived artifact with no recorded export/coverage incompleteness;
priority still remains provisional. Exit 1 means an incomplete artifact was
exported, or an input/selection/output error occurred (inspect stderr).
Exit 2 means invalid CLI usage. HTML requires `--report-file`. There is no new
Lead/investigation severity exit threshold. Default scan JSON remains unchanged.

## JSON schema v1

Top-level `kind` is `contextual-investigations`; `schema_version` and
`priority_policy_version` are integers `1`. Fields are `account_id`, `region`,
`incomplete`, `investigations`, scope-wide `coverage_gaps`, and `limitations`.
No export-time timestamp, new scan ID or raw Resource facts are copied.

Each investigation has:

| Fields | Meaning |
| --- | --- |
| `id`, `lead_id`, `pattern_id` | `investigation:` plus the unchanged full Lead ID; existing pattern and subject identity hashing. |
| `title`, `account_id`, `region`, `resources` | Logical scope and resource locators. Global IAM regions and unavailable ARNs stay null. AgentCore versions stay distinct, including relationship-only subjects. |
| `supporting_findings`, `supporting_relationships` | Entries with stable `id` and `reference`; exact original Lead support, without raw evidence copies. |
| `observed`, `inferred`, `unknown` | Condition arrays: `code`, `text`, `evidence` references (`kind`, `id`) and `assumptions`. Unknown conditions may have no evidence because the capability was not evaluated. |
| `coverage_gaps` | Stable `id`, `code`, account/region, optional service/resource/allowlisted operation, recorded status and bounded reason code. No arbitrary issue message is exported. |
| `priority`, `priority_status`, `priority_score` | HIGH/MEDIUM/LOW with PROVISIONAL; inconsistent support yields UNASSESSED/BLOCKED with null score. |
| `priority_factors`, `priority_explanation` | Each factor's code, bounded points, explanation and evidence references; the assessment's limits. |
| `explanation`, `recommended_actions` | Conservative review rationale and manual actions (`code`, `text`); no automatic execution. |

Finding and Relationship reference IDs are SHA-256 hashes of the existing
logical reference keys, with distinct kind prefixes; ARN remains a validated
locator rather than identity. Coverage IDs hash canonical gate fields. Resources,
conditions, references, gaps and investigations have deterministic ordering.
Arrays and objects are detached on serialization. Versioned artifacts are
described in [output contracts](output-contracts.md).

## Evidence semantics

**Observed** means directly supported normalized configuration: public addressing,
IMDS token setting, URL authentication, policy indicators, missing owner metadata,
recorded stale usage or positive workload-role binding. These conditions cite
the exact supporting checks/relationships, never just matching resource names.

**Inferred** means the existing deterministic conjunction warrants investigation.
It assumes saved configuration describes the collected observation and logical
identities connect its indicators. It does not establish exploitability.

**Unknown** includes unassessed effective permissions, reachability, business
criticality, non-exhaustive relationship inventory and the original Lead's
not-proven conditions. Public IP is not a route, broad policy is not effective
administration, and RUNS_AS configuration is not attacker credential access.

Invalid locators, ambiguous identities or mismatched support block assessment.
Candidate conditions move to unknown and graph relationships become unverified
associations. Missing optional evidence or permissions preserve supported positive
indicators while explicitly limiting the assessment. Snapshot v1 remains readable;
eligible finding-only patterns disclose `RELATIONSHIPS_UNSUPPORTED`. No v3 exists.
Missing evidence does not introduce a RESOLVED transition; existing
[Lead Delta](lead-delta.md) semantics remain authoritative.

## Priority policy 1

The score measures **configuration review urgency**, independently from Finding
severity, confidence, exploitation probability or monetary/business impact.
Each category contributes once, even if several overlapping checks support it:

| Category | Points | Evidence and justification |
| --- | --- | --- |
| Configuration exposure | 2 | LAMBDA-001 or EC2-005: URL authentication/public-address indicators warrant exposure review. Reachability remains unknown. |
| Broad permission indicator | 2 | IAM-001/002/003 or LAMBDA-002: broad policy configuration warrants effective-permission review. Boundaries, denies and SCPs can restrict it. |
| Metadata weakness | 1 | EC2-004: IMDSv1 permitted. Application request paths and credential access are unverified. |
| Governance or usage | 1 | IAM-007/009: owner metadata missing or stale-use indicator. Does not establish lack of business need. |
| Observed workload binding | 1 | Positive supporting RUNS_AS relationship connects a workload and role; no claim of invocation or credential retrieval. |

The total is bounded 0–7. HIGH >=5, MEDIUM 2–4, LOW 0–1.
With the usual positive relationship context, Lambda scores 5, EC2 6,
unowned workload role 4, stale role 3 and AI execution role 3. A historical
finding-only Lambda Lead scores 4 without an observed binding; no binding is
invented. More duplicate findings/edges never add points within a category.

Missing evidence never subtracts points or establishes safety. Coverage gaps
and policy incompleteness limit interpretation instead. Every current pattern
has material unknowns, so all assessed priorities are PROVISIONAL, including
complete exports. BLOCKED/UNASSESSED is reserved for inconsistent mandatory
identity/support and has no numerical score. No production status or asset
criticality is guessed: snapshots have no authoritative criticality contract.

## Graph interpretation

The existing standalone scan report keeps Leads, Relationships, Resources,
Findings, identity/suppression context and Coverage. Contextual mode also offers
a minimized standalone report. Both add an Investigation Graph and text records.

Select an investigation, highlight nodes by label, toggle inferred associations,
or select a node with mouse/keyboard to inspect its full label. The evidence link
opens the matching text record. Solid blue lines denote observed configuration
or finding/resource support; dashed gray lines denote review associations.
Neither style represents verified access. Blocked relationships are dashed.

Purple nodes are investigations; blue nodes are resources/roles; orange nodes
are supporting Findings; red nodes are coverage limitations. Graph labels are
shortened visually; the full label is available on selection. All condition,
priority, evidence-reference and action text remains available without JavaScript.

Only one graph is rendered at a time: at most 80 nodes/160 edges, and at most
100 investigation graphs are embedded. Omitted counts are displayed, edges to
omitted nodes are removed, and the full text investigation list is retained.
Investigations are selected in priority order before limits are applied.
Resource, Finding and coverage node kinds share the limited space, so many gaps
cannot displace every resource. Finding/resource associations use an identity
index. Search updates node opacity without recreating SVG elements. Standalone
contextual reports expand and restore evidence details for printing.
The graph uses inline SVG/JavaScript with no CDN, external fonts, backend or
network request. HTML is autoescaped; script data uses Jinja2 `tojson`; dynamic
labels use DOM `textContent`, never HTML interpolation. Reports still contain
sensitive resource names/ARNs: minimized does not mean anonymous.

See [architecture](architecture.md), [read-only validation](investigation-validation.md)
and [release notes](releases/v0.5.1.md) for implementation and verification limits.
