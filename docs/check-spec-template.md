# New security check specification template

Copy this template into a task-specific planning note before implementing a
check. It complements [Writing a security check](writing-checks.md). The
maintainer's local `NOW.md` and `SPEC.md`, when present, still define scope.

## Requirements and scope

- Stable proposed ID and service:
- User-visible risk indicator:
- What the check can verify from read-only AWS data:
- What it cannot verify (effective access, routing, policies, retention, etc.):
- Required AWS read permissions and regional/account scope:
- Existing check overlap and false-positive limits:

## Collector and normalized fact

- Collector entry point and `ScanContext` client:
- AWS operations and pagination:
- Resource type, ID/ARN and fact shape:
- Missing, denied, malformed and partial responses:
- Snapshot allowlist/validation changes and old-snapshot behavior:

## Rule and finding

- Required fact and secure/insecure decision:
- Severity with rationale:
- Evidence fields (allowlisted; no credentials or secret values):
- Risk, remediation and references:
- Catalog title/description and report presentation:

## Verification

- Insecure fixture produces the finding; secure fixture does not.
- AccessDenied and absent facts remain incomplete, never PASS.
- Pagination and duplicate handling are tested where the AWS API paginates.
- Offline snapshot replay matches live evaluation of normalized facts.
- Console, JSON and standalone HTML expose evidence and coverage safely.
- Focused tests and full local suite pass; no real AWS credentials in tests.
