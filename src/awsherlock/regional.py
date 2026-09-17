"""Sequential region orchestration with explicit coverage and shared sessions."""

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4
import json

from awsherlock import __version__
from awsherlock.aws.context import ScanContext
from awsherlock.aws.session import validate_region
from awsherlock.evaluation import Report, evaluate_snapshot, finalize_resource_selection
from awsherlock.snapshot import Snapshot, SnapshotError, capture_snapshot
from awsherlock.catalog import check_catalog

GLOBAL_SERVICES = {"iam", "s3"}
SnapshotSink = Callable[[Snapshot, str], None]


def parse_regions(value: str) -> list[str]:
    regions = value.split(",")
    for region in regions:
        validate_region(region)
    return list(dict.fromkeys(regions))


def collection_scopes(services: list[str], regions: list[str]) -> list[tuple[str | None, list[str]]]:
    global_services = [service for service in services if service in GLOBAL_SERVICES]
    regional_services = [service for service in services if service not in GLOBAL_SERVICES]
    scopes = [(None, global_services)] if global_services else []
    if regional_services:
        scopes.extend((region, regional_services) for region in regions)
    return scopes


def scan_regions(context: ScanContext, services: list[str], regions: list[str], *,
                 progress: Callable[[str, int, int], None] | None = None,
                 snapshot_sink: SnapshotSink | None = None,
                 selected_checks: list[str] | None = None,
                 selected_resources: list[str] | None = None,
                 report_unmatched: bool = True) -> Report:
    """Collect global services once and label every regional coverage entry."""
    # One cache per orchestration, never retained on the caller's context.
    context = replace(context, trail_status_cache={}, trail_selector_cache={})
    report = Report({"scan_id": str(uuid4()), "started_at": datetime.now(timezone.utc).isoformat(),
                     "account_id": context.account_id, "region": None, "regions": regions,
                     "version": __version__, "mode": "multi-region"}, [], [])
    scopes = collection_scopes(services, regions)
    total = sum(len(selected) for _, selected in scopes) + 1
    finished = 0
    seen_findings: set[str] = set()
    if selected_checks is not None:
        report.metadata["selected_checks"] = list(selected_checks)
    matched_resources = set()
    if selected_resources is not None:
        report.metadata["selected_resources"] = list(selected_resources)
    for region, selected in scopes:
        label = region or "global-bucket"
        target = replace(context, region=region) if region is not None else context
        if progress is not None:
            progress(f"Scanning {label}", finished, total)
        def service_progress(stage: str, completed: int, count: int) -> None:
            if progress is not None:
                progress(f"{label} / {stage}", finished + completed, total)
        try:
            snapshot = capture_snapshot(target, selected, progress=service_progress)
            if snapshot_sink is not None:
                snapshot_sink(snapshot, label)
            # A global/regional scope can contain only some requested check services.
            scope_ids = {identifier for identifier, service, _ in check_catalog() if service in selected}
            scope_checks = ([identifier for identifier in selected_checks if identifier in scope_ids]
                            if selected_checks is not None else None)
            result = evaluate_snapshot(snapshot, **({"selected_checks": scope_checks} if scope_checks is not None else {}),
                                       **({"selected_resources": selected_resources, "report_unmatched": False} if selected_resources is not None else {}))
            matched_resources.update(result.metadata.get("matched_resource_selectors", []))
            report.identities.extend(result.identities)
            entries = result.coverage
            for entry in entries:
                entry["findings"] = 0
            by_service = {entry["service"]: entry for entry in entries}
            for finding in result.findings:
                fingerprint = json.dumps(finding.to_dict(), sort_keys=True, ensure_ascii=False)
                if fingerprint in seen_findings:
                    continue
                seen_findings.add(fingerprint)
                report.findings.append(finding)
                by_service[finding.service]["findings"] += 1
        except SnapshotError:
            entries = [{"account_id": context.account_id, "service": service, "status": "ERROR",
                        "resources": 0, "evaluated": 0, "not_scanned": 0, "findings": 0,
                        "issues": [{"resource_id": None, "operation": "SnapshotValidation",
                                    "message": "Invalid normalized snapshot data"}]} for service in selected]
        for entry in entries:
            entry["region"] = region
            entry["scope"] = "bucket" if entry["service"] == "s3" else ("global" if region is None else "regional")
        report.coverage.extend(entries)
        finished += len(selected)
        if progress is not None:
            progress(f"{label} finished", finished, total)
    if progress is not None:
        progress("Regions evaluated", total, total)
    if selected_resources is not None:
        report.metadata["matched_resource_selectors"] = sorted(matched_resources)
        if report_unmatched:
            finalize_resource_selection(report)
    return report
