"""Observed-only finding history from explicit offline snapshots."""

import json

from awsherlock.diff import finding_key
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.snapshot import Snapshot


class HistoryError(ValueError):
    """Safe history input error."""


def finding_history(snapshots: list[Snapshot]) -> dict:
    if len(snapshots) < 2:
        raise HistoryError("History requires at least two snapshots")
    first = snapshots[0].metadata
    if any(snapshot.metadata.account_id != first.account_id or snapshot.metadata.region != first.region
           for snapshot in snapshots):
        raise HistoryError("History snapshots must have the same account and region scope")
    if any(earlier.metadata.started_at >= later.metadata.started_at
           for earlier, later in zip(snapshots, snapshots[1:])):
        raise HistoryError("History snapshots must be ordered by increasing collection time")
    if len({snapshot.metadata.scan_id for snapshot in snapshots}) != len(snapshots):
        raise HistoryError("History snapshots must have distinct scan IDs")
    observations = {}
    scans = []
    for snapshot in snapshots:
        report = evaluate_snapshot(snapshot)
        metadata = snapshot.metadata
        stamp = metadata.started_at.isoformat()
        coverage = {row["service"]: row["status"] for row in report.coverage}
        scans.append({"scan_id": metadata.scan_id, "started_at": stamp,
                      "coverage": coverage, "incomplete": report.incomplete})
        for finding in report.findings:
            key = finding_key(finding)
            item = observations.get(key)
            if item is None:
                item = {"check_id": finding.id, "title": finding.title, "severity": finding.severity.value,
                        "service": finding.service, "account_id": finding.account_id,
                        "region": finding.region, "resource_id": finding.resource_id,
                        "first_observed_at": stamp, "first_scan_id": metadata.scan_id,
                        "last_observed_at": stamp, "last_scan_id": metadata.scan_id,
                        "observed_scan_count": 0}
                observations[key] = item
            if item["last_scan_id"] != metadata.scan_id or item["observed_scan_count"] == 0:
                item["observed_scan_count"] += 1
            item["last_observed_at"] = stamp
            item["last_scan_id"] = metadata.scan_id
            item["severity"] = finding.severity.value
            item["title"] = finding.title
    return {"schema_version": 1, "kind": "finding-history", "account_id": first.account_id,
            "region": first.region, "scans": scans,
            "findings": [observations[key] for key in sorted(observations)],
            "incomplete": any(scan["incomplete"] for scan in scans)}


def render_history_json(history: dict) -> str:
    return json.dumps(history, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
