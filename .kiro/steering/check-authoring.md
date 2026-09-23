---
inclusion: auto
name: awsherlock-check-authoring
description: Apply AWSherlock security-check architecture and evidence rules when adding or changing a scanner check.
---

# AWSherlock check authoring

Read `docs/writing-checks.md` and `docs/check-spec-template.md` before editing
a check. If local `SPEC.md` and `NOW.md` are present, follow their active scope;
they are maintainer-only files and must not be committed.

- Keep SDK sessions in the authentication/context layer. Collectors receive a
  `ScanContext` and make read-only calls.
- Collect normalized facts, then evaluate them in a rule; emit the shared
  `Finding` model with a stable ID, evidence, risk and remediation.
- Missing or denied facts must remain incomplete coverage, never PASS.
- Cover insecure and secure fixtures, denial, pagination when relevant, and
  offline snapshot replay. Verify catalog/help and JSON/HTML/console output.
- Do not export credentials, tokens, raw events or secret values.
- Keep a new check within the approved service scope; avoid unrelated refactors.
