# Architecture

AWSherlock keeps AWS authentication, collection, normalized facts, evaluation
and presentation separate. Python >=3.11 is required. The investigation engine
adds no dependencies or AWS API calls.

## Data flow

1. `aws/session.py` verifies the caller/expected account and creates `ScanContext`.
   Collectors receive that context and use its cached SDK clients.
2. `registry.py` describes 11 services, seven default selections, 42 checks and
   normalized fact allowlists. Collectors retain valid facts alongside sanitized
   `CollectionIssue` failures. No secret-value retrieval occurs.
3. `snapshot.py` saves normalized Resources and positive Relationships as schema
   v2. Readers validate historical v1/v2 without enrichment. `relationships.py`
   reconciles exact logical endpoints and locators; missing edges are unknown.
4. `evaluation.py` reuses registered deterministic rules to produce a scope-local
   `Report`. Required missing facts and failed reads remain incomplete coverage.
5. `leads.py` correlates that exact Report with its snapshot through immutable
   indexes in `correlation.py`. Five existing Lead patterns and IDs are unchanged.
6. `investigation_engine.py` adapts those Leads once per scope. The engine uses
   `investigation.py`'s support adapter and `lead_delta.py`'s locator gates, then
   attaches typed evidence references, conditions, priority factors and actions.
   `investigation_models.py` serializes detached, deterministic schema-v1 results.
7. `reporting.py` renders contextual JSON/HTML. `html_report.py` preserves exact
   live/offline scope reports and assembles existing sections plus investigations.
   `investigation_graph.py` builds bounded graph data; Jinja2 escapes HTML and
   script JSON, while inline JavaScript creates SVG with DOM APIs/textContent.

Report-only HTML callers still work with an explicit context-unavailable state.
Supplied evaluation reports retain check/resource selectors and suppression
annotations; investigations do not reevaluate excluded findings into existence.
Default scan JSON, Lead v2, Evidence Pack v1, Coverage Diagnostics v1, diff and
Lead Delta contracts remain unchanged. Contextual output is a separate artifact.

## Evidence boundaries

Observed conditions cite exact Finding or Relationship references. Inferred
review associations cite the conjunction's evidence and list assumptions.
Unassessed access, reachability, criticality and exploitability remain unknown.
Identity conflicts block priority and move candidate observations to unknown;
no conflicting candidate relationship becomes a solid observed graph edge.

Coverage is scoped. Service COMPLETE means selected supported evaluation, never
exhaustive inventory, effective access, or account security. Scope gaps remain
visible even when no investigation can be generated. Relevant incomplete
coverage, missing policy context and unsupported relationship schemas are
attached to each investigation. No temporal resolution state is invented:
Lead Delta continues to require a validated false predicate for disappearance.

## Maintenance boundaries

New Lead patterns belong in the existing correlation registry. An adapter must
map each new observed statement to explicit supporting predicates before the
engine accepts it; unmapped statements fail closed. Priority categories should
remain small, bounded and versioned independently from finding severity.

The Evidence Pack and engine deliberately reuse current Lead Delta support
gates through `assess_lead_support`; a future extraction into a dedicated support
module may reduce private-helper coupling. This release avoids moving existing
comparison policy or changing its semantics. Historical snapshots lack optional
relationship-family completion and IAM incarnation IDs; these remain explicit
limitations. No routing/NACL analysis, effective-policy simulator, arbitrary tag
criticality inference, remediation or confirmed attack-path model is included.

Scope-wide contextual coverage shares `coverage_intelligence.coverage_issue_rows`
with Coverage Diagnostics, using exact bounded reason and operation allowlists
for all supported services. The historical Evidence Pack export policy remains
separate for compatibility. Collectors additionally normalize known throttling
and request-timeout codes; no new retry loop or global retry override was added.
