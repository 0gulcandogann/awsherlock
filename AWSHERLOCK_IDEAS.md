# AWSherlock — Strategic ideas (second idea group)

This file preserves the second idea group as a distinct, high-priority planning
source. [IDEAS.md](IDEAS.md) holds the general backlog; [MILESTONES.md](MILESTONES.md)
records development labels and Git tag gates. Priorities here do not override
`NOW.md` or `SPEC.md`. Suggested version bands below are themes, not scheduled
releases or permission to create tags.

## Product direction

Answer four questions: What is risky? What changed? Did a deployment add risk?
What should an engineer investigate next? Keep the product small, read-only,
offline-capable and honest about missing evidence. Prioritize high-signal checks
and useful workflows over check count.

## S-01 — Change detection and CI workflow (suggested v0.2 theme)

1. **`awsherlock diff`:** compare two snapshots using stable finding/resource
   identity. Show NEW, RESOLVED and UNCHANGED. A missing permission or narrower
   scope must remain unknown, not RESOLVED. Allow severity/service filtering only
   after the comparison semantics are defined.
2. **Baseline and expiring suppressions:** record check/resource, reason, owner
   and expiry in an explicit file. Keep suppressed findings auditable; show
   suppressed and expired counts. A possible `.awsherlock.yaml` also needs
   precedence/schema rules and must never hold credentials.
3. **Automation thresholds:** define `--fail-on` for high/critical or *new*
   findings. Specify exit codes without changing today's incomplete-scan exit 1
   silently. Consider `--ci`, `--quiet` and `--no-progress` only for concrete CI
   use cases; `--no-progress` already exists.
4. **Scanner CI:** test PRs and pushes with mocked AWS responses, package build
   and installed CLI/offline smoke. The current GitHub Actions workflow is for
   publishing, so this is separate work. Real AWS credentials are not needed.

General IDEA-001, IDEA-008 and IDEA-009 overlap this theme. Their detailed
product direction lives here; their original IDs remain in `IDEAS.md`.

## S-02 — Kiro contributor workflow (suggested v0.2.x theme)

`AGENTS.md` already exists. Consider optional repository steering, a new-check
spec template, targeted test hooks and a security-review agent. Reuse the
existing architecture and rules instead of maintaining conflicting guidance.

For each new check, the template should request requirements, collector/fact
design, rule/evidence/remediation, secure/insecure/denied/offline fixtures and
catalog/report verification. A hook may run relevant tests after rule changes;
a reviewer may check read-only AWS calls, missing-permission false PASS, secret
exposure, severity and duplicate checks. Hook automation must not modify AWS.

This is a contributor aid, not a generic AWSherlock plugin system. It does not
require moving every existing test or redesigning the rule engine.

## S-03 — Broader security coverage (suggested v0.3 theme)

Each item here **requires an explicit `SPEC.md` change** before implementation.

- **Compliance mappings:** start with a small CIS AWS Foundations or AWS FSBP
  mapping. Report implemented/evaluated/missing controls; never claim blanket
  compliance or certification from partial coverage.
- **RDS:** candidate checks for public access, storage encryption, deletion
  protection, backup retention, TLS, IAM authentication and public snapshots.
  Choose a bounded first subset with read permissions and false-positive limits.
- **Security-service posture:** potential GuardDuty, Security Hub, Config and
  Inspector presence/configuration checks. Access Analyzer is currently approved
  only as optional identity evidence.
- **AI security pack:** possible Bedrock logging/guardrails/access, AgentCore
  tool and execution-role scope, and SageMaker network/encryption. Current
  Bedrock/AgentCore approval covers identity metadata only.
- **OCSF export:** map normalized findings to an external schema for a proven
  SIEM/Security Lake use case; keep internal findings independent of the format.

SARIF and GitHub code scanning are also out of v0.1 scope and need a `SPEC.md`
change. They remain general IDEA-007, not part of the initial OCSF proposal.

## S-04 — Investigation and scale (suggested v0.4 theme)

- **Exposure chains:** correlate findings such as public Lambda URL → role →
  broad access as investigation leads. Do not label them exploit paths without
  modeling policies, boundaries, explicit deny, conditions and SCPs. An
  attack-path engine or graph visualization needs a `SPEC.md` change.
- **Finding history:** first/last seen needs explicit prior scans or a durable
  history input. A single scan cannot infer these timestamps.
- **Bounded concurrency:** measure organization scans before adding workers.
  Specify SDK client safety, per-service rates, bounded queues, deterministic
  output and account/region error isolation. Keep SDK retry behavior bounded.
- **Finding quality:** show the exact normalized evidence, risk and actionable
  remediation. Explain what was verified and what could not be verified. Never
  expose secrets or claim effective access from a configuration indicator.

## Milestone rule

Break one theme into a small `NOW.md` contract before writing code. Assign its
development label in `MILESTONES.md`; mark `COMPLETE` only after that contract's
Done when and tests are satisfied. A `vX.Y.Z` Git tag belongs to a separate
release milestone and must wait for all included work to be complete, reviewed
source/version alignment and explicit owner release authorization.
