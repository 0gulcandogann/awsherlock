# Changelog

## Unreleased

- Running `awsherlock` without arguments now displays help and exits successfully,
  without creating an AWS session.
- Added `awsherlock --update` to refresh an existing installation from GitHub.
- Document user-wide pipx installation, PATH setup, upgrades and removal for
  Windows, macOS and Linux.
- Added `install.sh` for a sudo-free, isolated Linux/macOS installation from a
  local checkout.
- Made clone-based installation the primary README flow; pipx, where used, now
  installs from that local clone instead of a remote package URL.
- Refreshed the standalone HTML report with a stronger visual hierarchy, status
  stamp, card styling and severity bars. Human-facing terminal output and the
  installer now share a Unicode AWSherlock banner; JSON remains unchanged.

## 0.1.0 — 2026-09-16

Initial release candidate for a read-only AWS security CLI.

- 28 configuration checks across IAM, S3, EC2, Lambda, Secrets Manager,
  CloudTrail and KMS.
- Standard AWS SDK credential chain, profiles, existing SSO sessions and STS
  AssumeRole with temporary credentials held only in memory.
- Organizations account discovery and sequential role-based multi-account scans,
  including visible inaccessible and inactive accounts.
- Versioned snapshot capture and offline evaluation using the same rule engine.
- Console, JSON and standalone HTML reports with search, severity/service/account
  filters, stable sorting, evidence, remediation and permission coverage.
- COMPLETE, PARTIAL, ACCESS_DENIED, ERROR and NOT_SCANNED coverage per account/service.
- Python packaging, non-root Docker image and synthetic offline examples.

Limits: configured region only for regional services; no effective IAM access
simulation or live AWS validation. Explicit assumed-role credentials do not refresh.
Unknown Lambda runtimes remain incomplete. Organization snapshot capture, OU/SCP
analysis, remediation and compliance certification are outside this release.

Exit codes: 0 for completed evaluation (even with findings), 1 for incomplete
coverage or operational errors, 2 for invalid CLI usage. Plain `scan` now scans
all supported services; it no longer stops after displaying identity.
