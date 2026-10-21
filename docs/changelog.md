# Changelog

## v0.5.1 — Unreleased

**Substantial feature release under a patch version number.** The package
version changed by maintainer direction; the complete investigation scope is
retained. No Finding severity, Lead ID or public schema version was renamed to
match the package version.

- Evidence-Aware Investigation Engine over all five existing Lead patterns,
  stable evidence references, observed/inferred/unknown conditions, coverage
  gates, explicit assumptions and recommended manual actions.
- Contextual review priority with bounded 0–7 scoring and explained factors,
  PROVISIONAL assessments and BLOCKED identity conflicts. No effective-IAM,
  internet-reachability, exploitability or asset-criticality assumptions.
- `investigate --contextual` JSON/standalone HTML, optional exact Lead selection,
  interactive offline SVG graph and accessible text evidence. Existing scoped
  scan HTML keeps all prior sections and adds the investigation view.
- Graph improvements prioritize high urgency under limits, balance node kinds,
  index Finding/resource joins and highlight search results without rebuilding
  the graph. Standalone print preserves access to all evidence details.
- Scope coverage reuses bounded Coverage Intelligence diagnostics across all
  services. Additional throttling/timeout errors are sanitized; retry settings
  stay inherited. Synthetic retry tests make no AWS calls.

Snapshot v1/v2, Lead Delta, Evidence Packs, existing scan JSON, CLI thresholds
and v0.5.0 workflows remain compatible. Tests, read-only validation infrastructure,
release checks and documentation are expanded. Browser execution remains subject
to local IPC permissions; live AWS results are not claimed. See
[release notes](releases/v0.5.1.md) and the
[validation record](releases/v0.5.1-validation.md).

Final readiness work adds optional pinned Ruff/Black development tools and
shared configuration without changing runtime dependencies. The exact
`SO_PASSCRED` browser startup denial and normal-terminal follow-up commands are
recorded in the [readiness report](releases/v0.5.1-readiness.md). All Ruff findings
are resolved and Black formatting passes across 162 Python files. Shared pytest
fixture registration preserves the same providers and scopes for all 1773 tests.
The user reported all six Chrome browser tests passing in a normal Omarchy
terminal; Codex-local browser execution remains blocked. The
[final publication gate](releases/v0.5.1-final-release-gate.md) records candidate
checksums, packaging evidence and remaining Twine/remote availability blockers.

## v0.5.0

Evidence-aware Lead Delta, minimized Investigation Evidence Packs, AgentCore
production-routing context and offline Coverage Intelligence. Historical release
details remain in [v0.5.0 notes](releases/v0.5.0.md).

## Earlier releases

See the historical [v0.4.0 notes](releases/v0.4.0.md) and README release history.
