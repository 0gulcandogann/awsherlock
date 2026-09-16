"""Read-only organization discovery and sequential account orchestration."""

import re
from dataclasses import replace
from collections.abc import Callable
from datetime import datetime, timezone
from uuid import uuid4

from awsherlock import __version__
from awsherlock.aws.context import ScanContext
from awsherlock.aws.session import SessionError, create_scan_context
from awsherlock.collectors.common import AWS_ERRORS, InvalidResponse, error_message, items, text_field
from awsherlock.evaluation import Report, evaluate_snapshot
from awsherlock.coverage import coverage_status
from awsherlock.snapshot import SnapshotError, capture_snapshot
from awsherlock.regional import SnapshotSink, collection_scopes, scan_regions


def scan_organization(source: ScanContext, services: list[str], role_name: str = "AWSherlockAuditRole",
                      external_id: str | None = None, role_session_name: str | None = None,
                      progress: Callable[[str, int, int], None] | None = None,
                      regions: list[str] | None = None,
                      snapshot_sink: SnapshotSink | None = None,
                      selected_checks: list[str] | None = None,
                      selected_accounts: list[str] | None = None) -> Report:
    if not re.fullmatch(r"(?:[A-Za-z0-9_+=,.@-]+/)*[A-Za-z0-9_+=,.@-]{1,64}", role_name):
        raise SessionError("Invalid organization role name or path.")
    report = Report({"scan_id": str(uuid4()), "started_at": datetime.now(timezone.utc).isoformat(),
                     "account_id": source.account_id, "region": source.region, "version": __version__,
                     "mode": "organization", "accounts": []}, [], [])
    accounts = report.metadata["accounts"]
    if selected_checks is not None:
        report.metadata["selected_checks"] = list(selected_checks)
    if selected_accounts is not None:
        report.metadata["selected_accounts"] = list(selected_accounts)
    if regions is not None:
        report.metadata.update(region=None, regions=regions)
    def account_failures(account_id: str, operation: str, message: str,
                         status: str = "ERROR") -> None:
        scopes = collection_scopes(services, regions) if regions is not None else [(None, services)]
        for region, selected in scopes:
            for service in selected:
                entry = failed_coverage(account_id, service, operation, message, status)
                if regions is not None:
                    entry.update(region=region, scope="bucket" if service == "s3" else ("global" if region is None else "regional"))
                report.coverage.append(entry)
    seen = set()
    if progress is not None:
        progress("Discovering accounts", 0, 1)
    try:
        client = source.client("organizations")
        for page in client.get_paginator("list_accounts").paginate():
            for raw in items(page, "Accounts"):
                if not isinstance(raw, dict) or not isinstance(raw.get("Id"), str) or not re.fullmatch(r"[0-9]{12}", raw["Id"]):
                    raise InvalidResponse()
                account = {"account_id": raw["Id"], "name": text_field(raw.get("Name")),
                           "state": text_field(raw.get("State"))}
                if account["account_id"] in seen:
                    continue
                seen.add(account["account_id"])
                accounts.append(account)
    except AWS_ERRORS as error:
        report.coverage.append(failed_coverage(source.account_id, "organizations", "ListAccounts", error_message(error)))
    if progress is not None:
        progress("Accounts discovered", 1, len(accounts) + 2)
    for index, account in enumerate(accounts):
        account_id = account["account_id"]
        if progress is not None:
            progress(f"Scanning account {account_id}", index + 1, len(accounts) + 2)
        if selected_accounts is not None and account_id not in selected_accounts:
            account["scan_status"] = "NOT_SCANNED"
            account_failures(account_id, "AccountSelection", "Account excluded by --accounts", "NOT_SCANNED")
            if progress is not None:
                progress(f"Account {account_id} excluded", index + 2, len(accounts) + 2)
            continue
        if account["state"] != "ACTIVE":
            account["scan_status"] = "NOT_SCANNED"
            account_failures(account_id, "AccountState", "Account is not ACTIVE", "NOT_SCANNED")
            if progress is not None:
                progress(f"Account {account_id} skipped", index + 2, len(accounts) + 2)
            continue
        try:
            context = create_scan_context(source_session=source.session,
                                          role=f"arn:{source.partition}:iam::{account_id}:role/{role_name}",
                                          external_id=external_id, role_session_name=role_session_name,
                                          **({"client_config": source.client_config} if source.client_config is not None else {}))
            if source.measurements is not None:
                context = replace(context, measurements=source.measurements)
            if regions is not None:
                result = scan_regions(context, services, regions, snapshot_sink=snapshot_sink,
                                      **({"selected_checks": selected_checks} if selected_checks is not None else {}))
            else:
                snapshot = capture_snapshot(context, services)
                if snapshot_sink is not None:
                    snapshot_sink(snapshot, context.region or "global")
                result = evaluate_snapshot(snapshot, **({"selected_checks": selected_checks} if selected_checks is not None else {}))
        except (SessionError, SnapshotError) as error:
            account["scan_status"] = coverage_status([{"message": str(error)}], 0, 0)
            operation = "AssumeRole" if isinstance(error, SessionError) else "SnapshotValidation"
            account_failures(account_id, operation, str(error))
            if progress is not None:
                progress(f"Account {account_id} unavailable", index + 2, len(accounts) + 2)
            continue
        report.findings.extend(result.findings)
        report.coverage.extend(result.coverage)
        account["scan_status"] = "PARTIAL" if result.incomplete else "COMPLETE"
        if progress is not None:
            progress(f"Account {account_id} finished", index + 2, len(accounts) + 2)
    if progress is not None:
        progress("Finalizing results", len(accounts) + 1, len(accounts) + 2)
    if selected_accounts is not None:
        for account_id in selected_accounts:
            if account_id not in seen:
                account_failures(account_id, "AccountSelection", "Selected account was not discovered", "NOT_SCANNED")
    return report


def failed_coverage(account_id: str, service: str, operation: str, message: str, status: str = "ERROR") -> dict:
    if status == "ERROR":
        status = coverage_status([{"message": message}], 0, 0)
    return {"account_id": account_id, "service": service, "status": status,
            "resources": 0, "evaluated": 0, "not_scanned": 0, "findings": 0,
            "issues": [{"resource_id": None, "operation": operation, "message": message}]}
