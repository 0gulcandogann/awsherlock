# AWSherlock — Development labels and Git tag gate

Use a development label to identify each bounded piece of work. A development
label is a planning ID, **not** a Git tag. `NOW.md` defines the active scope and
Done when; `SPEC.md` defines product boundaries. A Git `vX.Y.Z` tag is reserved
for a completed, separately authorized release and must never be used to mark
work in progress.

## Status meanings

| Status | Meaning |
| --- | --- |
| PROPOSED | Idea only; no active contract or release commitment. |
| PLANNED | Bounded scope and Done when are written; implementation may begin when authorized. |
| IN_PROGRESS | The current `NOW.md` contract is being implemented. |
| COMPLETE | The contract's Done when, relevant tests and reviewable evidence are satisfied. This status alone does not authorize a Git tag. |
| RELEASED | An authorized Git tag was created and the publication outcome was verified. |

## Development labels

| Label | Work | Status | Evidence / remaining work |
| --- | --- | --- | --- |
| DEV-CLI-001 | Local `scan --preview` | COMPLETE | `NOW.md` 2026-09-22 contract; 168 relevant tests passed, README/help updated. Included in released 0.1.15. |
| DEV-TOOL-001 | Explain incomplete CloudTrail facts | COMPLETE | `NOW.md` 2026-09-22 contract; 127 focused tests passed. Included in released 0.1.15. |
| DEV-TOOL-002 | Opt-in SDK measurement file | COMPLETE | `NOW.md` 2026-09-22 contract; five focused CLI integration tests and 860 full local tests passed. Next larger release batch; no tag assigned. |
| STRAT-S-01..04 | Second idea group's strategic themes | PROPOSED | See `AWSHERLOCK_IDEAS.md`; split into bounded contracts before development. |

## Release tag ledger

| Git tag | Status | Included scope | Gate |
| --- | --- | --- | --- |
| `v0.1.0`, `v0.1.5`, `v0.1.10` | RELEASED | Historical releases | Existing tags stay unchanged. |
| `v0.1.15` | RELEASED | DEV-CLI-001 and DEV-TOOL-001 only | Owner authorized tag/push; Trusted Publisher workflow and both index verifications passed. |
| Next larger release (tag TBD) | PROPOSED | Multiple completed development labels; scope to be selected one contract at a time | A single completed label or documentation fix does not trigger a tag. Complete and verify the cohesive batch, then obtain separate owner release authorization. |

### v0.1.15 local evidence (2026-09-22)

- Regenerated the ignored synthetic demo HTML from its snapshot; the demo test
  now passes. No example or test fixture enters the published package.
- Full local test suite: 855 passed on Python 3.13. Source/tag string validation
  accepts `v0.1.15` and rejects mismatches through existing release tests.
- One 0.1.15 wheel and sdist built in `reports/release-0.1.15/dist` with isolated
  Hatchling. Strict Twine and archive/version/license/template checks passed.
- Wheel SHA256: `ede8bec67d58cffbfbddca45a0a85b9cd79af71b356b6c36af490bfbab9b7f18`.
  Sdist SHA256: `a9b4417d896cde481a63de24452e3b823e1b76fd024561da983268daba9170e5`.
- A fresh local Python 3.13 environment installed the wheel with resolved
  dependencies; `pip check` and installed CLI/offline JSON/HTML smoke passed.
  Smoke blocks AWS/network and covers preview plus CloudTrail missing facts.
- README shows candidate 0.1.15 while the published badge still links 0.1.10.
  Local evidence does not exercise OIDC publication.

### v0.1.15 remote pre-tag evidence (2026-09-22)

- Preparation commit `f320db7` was pushed to `main`. The
  [validation-only workflow run](https://github.com/0gulcandogann/awsherlock/actions/runs/35752595756)
  passed build, Linux 3.11/3.13, macOS 3.13 and Windows 3.13 fresh-install
  smoke. TestPyPI/PyPI publish and index-verification jobs correctly skipped.
- PyPI and TestPyPI 0.1.15 JSON endpoints both returned HTTP 404 at the
  pre-tag check. Version availability must be rechecked when tagging.
- The final milestone-status commit changes this ledger only; the validated
  package source, version, workflow and README stay at `f320db7` content.
- Actual OIDC upload, published hashes and index installation remain untested
  until an explicitly authorized tag push. This milestone's COMPLETE status
  records pre-tag readiness only, not a release.

### v0.1.15 publication evidence (2026-09-22)

- Owner explicitly authorized release after successful tests. Annotated tag
  `v0.1.15` points to `c89ce0a` and was pushed without moving an older tag.
- [Tag-triggered workflow run](https://github.com/0gulcandogann/awsherlock/actions/runs/35753275008)
  completed successfully: build, all four fresh-install jobs, Trusted Publisher
  uploads to TestPyPI and PyPI, downloaded hash checks and installed smoke on
  both indices.
- The workflow's own wheel and sdist were downloaded and separately checked
  against both published indices. Wheel SHA256:
  `30070631828d8baf23926feabe4c1707afa66f5327a993d8f610b242f9a28e14`;
  sdist SHA256:
  `152c98724ac8dbc20b06dde2c9ecff969f6f9492c3ffe0af0662d9c7165396bb`.
- The earlier local pre-tag build has different byte hashes. It passed its own
  checks but is not the published artifact; use the workflow artifact hashes
  above for release verification.

Before any new Git tag:

1. Record the exact included development labels and release Done when here.
2. Mark every included label `COMPLETE` only after its `NOW.md` Done when and
   relevant tests pass. Resolve release-blocking failures and record limits.
3. Verify the full release checks, package build and installed smoke; align
   `__version__`, documentation and the intended `vX.Y.Z` tag with one commit.
4. Record the release milestone as `COMPLETE` here, then obtain explicit owner
   authorization for the tag/push. Pushing a `v*` tag triggers publication.
5. Create the tag on the verified commit and record the remote publication
   outcome as `RELEASED` only after it is verified.

Do not reuse an existing version or move an existing release tag. A planning
label, completed feature or green subset of tests cannot bypass these gates.
