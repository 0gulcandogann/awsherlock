"""Conservative, offline comparison of two normalized snapshots."""

import json
from collections import Counter

from awsherlock.evaluation import evaluate_snapshot
from awsherlock.models import Finding
from awsherlock.snapshot import Snapshot


SCHEMA_VERSION = 1


def finding_key(finding: Finding) -> tuple[str, str, str, str, str]:
    return (finding.id, finding.service, finding.account_id,
            finding.region or "", finding.resource_id)


def compare_snapshots(before: Snapshot, after: Snapshot) -> dict:
    """Compare observed findings; unresolved coverage always produces UNKNOWN."""
    previous = evaluate_snapshot(before)
    current = evaluate_snapshot(after)
    old = Counter(finding_key(finding) for finding in previous.findings)
    new = Counter(finding_key(finding) for finding in current.findings)
    details = {finding_key(finding): finding for finding in (*previous.findings, *current.findings)}
    old_coverage = {row["service"]: row["status"] for row in previous.coverage}
    new_coverage = {row["service"]: row["status"] for row in current.coverage}
    same_scope = (before.metadata.account_id == after.metadata.account_id and
                  before.metadata.region == after.metadata.region)
    changes = []
    for key in sorted(old.keys() | new.keys()):
        finding = details[key]
        before_count, after_count = old[key], new[key]
        if before_count and after_count:
            status = "UNCHANGED"
        elif not same_scope:
            status = "UNKNOWN"
        elif after_count:
            status = "NEW" if old_coverage.get(finding.service) == "COMPLETE" else "UNKNOWN"
        else:
            status = "RESOLVED" if new_coverage.get(finding.service) == "COMPLETE" else "UNKNOWN"
        changes.append({"status": status, "check_id": finding.id, "title": finding.title,
                        "severity": finding.severity.value, "service": finding.service,
                        "account_id": finding.account_id, "region": finding.region,
                        "resource_id": finding.resource_id,
                        "before_count": before_count, "after_count": after_count})
    counts = {status: sum(change["status"] == status for change in changes)
              for status in ("NEW", "RESOLVED", "UNCHANGED", "UNKNOWN")}
    return {"schema_version": SCHEMA_VERSION, "kind": "snapshot-diff",
            "before": {"scan_id": before.metadata.scan_id, "account_id": before.metadata.account_id,
                       "region": before.metadata.region, "started_at": before.metadata.started_at.isoformat()},
            "after": {"scan_id": after.metadata.scan_id, "account_id": after.metadata.account_id,
                      "region": after.metadata.region, "started_at": after.metadata.started_at.isoformat()},
            "same_scope": same_scope,
            "coverage": {"before": old_coverage, "after": new_coverage},
            "summary": counts, "changes": changes}


def render_diff_json(comparison: dict) -> str:
    return json.dumps(comparison, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
