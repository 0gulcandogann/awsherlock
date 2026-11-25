# Changelog

## Unreleased — visual report

Presentation only. Scan JSON, Lead v2, Evidence Pack v1, snapshot, diff and Lead
Delta contracts are unchanged. The report stays one offline file with inline
CSS, JS and SVG, no external fonts, libraries or images.

- Investigation Graph is split into two tabs. **Architecture** shows the
  resources and configuration relationships that investigations refer to, in
  lanes (compute, identity, data, AI, monitoring). **Review paths** shows the
  evidence behind one investigation in columns. Neither view claims an attack
  path; the legend and every detail panel say so.
- Edge styles separate observed (solid), inferred (dashed) and coverage
  limitation (dotted). Selecting a node opens a detail panel with connections.
  Arrow keys move between nodes and tabs follow the ARIA tabs pattern.
- Review paths is a tree: the investigation on top, resources below it, each
  resource's findings nested under it, joined by orthogonal rails so no line
  crosses a card or another line. Resource-to-resource relationships are drawn as
  brackets on the right. Architecture orders cards inside each lane by their
  neighbours to keep connections short.
- Architecture fans connection points out along each card side and replaces a
  pile of identical inline labels with one summary line when there are more than
  three edges. The stat counters finish even when the page opens in a background
  tab or is printed right away.
- Tables no longer split headers or status badges inside a word when the page is
  zoomed or narrow ("Resour/ces", "COMPLE/TE"). Only long identifiers and ARNs
  still wrap anywhere; the table scrolls sideways when it must.
- Responsive sweep at 320–1600 px: Architecture sizes itself to its container and
  redraws on resize, Review paths drops its fixed minimum width, narrow screens
  get a "scroll sideways" hint, the hero stacks below 900 px, service tiles go
  two per row on phones with scaling icons, and long condition codes break after
  underscores instead of mid-word.
- Inline cloud-and-magnifier favicon (a `data:` URI, no external file).
- Own inline SVG glyphs for 11 services plus a generic fallback, with AWS-style
  category colors. Color is never the only signal; labels name each service.
- Motion: one hero scan sweep, counting stat tiles, filling severity bars, and a
  staged reveal of graph nodes and edges. All motion is opt-in through
  `prefers-reduced-motion: no-preference` and is removed in print.
- Layout fixes inside the existing visual identity (mono type, purple frames,
  orange offset shadows): the Investigation Graph now sits right after the Leads,
  the nav gains a "Graph" link, the footer moves to the end of the page, findings
  show their service icon, and a severity distribution bar sits above the counts.
  Screenshots are in `docs/assets/`.
- New synthetic `examples/demo-investigation-snapshot.json` (two Leads) built by
  `scripts/build_investigation_demo.py`. `examples/demo-report.html` was
  regenerated because the report now carries the inline glyph sprite.

## v0.5.1 — 2026-10-21

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
After access was enabled, an independent full suite passed **1779 tests**,
including eight Chrome browser cases. Visual review found and fixed standalone
graph-control overflow; 375px/1440px regressions cover long investigation titles.
Strict Twine verification passed. The
[final publication gate](releases/v0.5.1-final-release-gate.md) records the local
checks, clean-commit publishing process and historical candidate provenance.

## v0.5.0

Evidence-aware Lead Delta, minimized Investigation Evidence Packs, AgentCore
production-routing context and offline Coverage Intelligence. Historical release
details remain in [v0.5.0 notes](releases/v0.5.0.md).

## Earlier releases

See the historical [v0.4.0 notes](releases/v0.4.0.md) and README release history.
