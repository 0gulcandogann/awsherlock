"""Read-only organization discovery and sequential account orchestration."""

import re
from datetime import datetime, timezone
from uuid import uuid4

from awsherlock import __version__
from awsherlock.aws.context import ScanContext
from awsherlock.aws.session import SessionError, create_scan_context
from awsherlock.collectors.common import AWS_ERRORS, InvalidResponse, error_message, items, text_field
from awsherlock.evaluation import Report, evaluate_snapshot
from awsherlock.coverage import coverage_status
from awsherlock.snapshot import SnapshotError, capture_snapshot


def scan_organization(source: ScanContext, services: list[str], role_name: str = "AWSherlockAuditRole",
                      external_id: str | None = None, role_session_name: str | None = None) -> Report:
    if not re.fullmatch(r"(?:[A-Za-z0-9_+=,.@-]+/)*[A-Za-z0-9_+=,.@-]{1,64}", role_name):
        raise SessionError("Invalid organization role name or path.")
    report = Report({"scan_id": str(uuid4()), "started_at": datetime.now(timezone.utc).isoformat(),
                     "account_id": source.account_id, "region": source.region, "version": __version__,
                     "mode": "organization", "accounts": []}, [], [])
    accounts = report.metadata["accounts"]
    seen = set()
    try:
        client = source.session.client("organizations")
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
    for account in accounts:
        account_id = account["account_id"]
        if account["state"] != "ACTIVE":
            account["scan_status"] = "NOT_SCANNED"
            for service in services:
                report.coverage.append(failed_coverage(account_id, service, "AccountState", "Account is not ACTIVE", "NOT_SCANNED"))
            continue
        try:
            context = create_scan_context(source_session=source.session,
                                          role=f"arn:{source.partition}:iam::{account_id}:role/{role_name}",
                                          external_id=external_id, role_session_name=role_session_name)
            result = evaluate_snapshot(capture_snapshot(context, services))
        except (SessionError, SnapshotError) as error:
            account["scan_status"] = coverage_status([{"message": str(error)}], 0, 0)
            for service in services:
                operation = "AssumeRole" if isinstance(error, SessionError) else "SnapshotValidation"
                report.coverage.append(failed_coverage(account_id, service, operation, str(error)))
            continue
        report.findings.extend(result.findings)
        report.coverage.extend(result.coverage)
        account["scan_status"] = "PARTIAL" if result.incomplete else "COMPLETE"
    return report


def failed_coverage(account_id: str, service: str, operation: str, message: str, status: str = "ERROR") -> dict:
    if status == "ERROR":
        status = coverage_status([{"message": message}], 0, 0)
    return {"account_id": account_id, "service": service, "status": status,
            "resources": 0, "evaluated": 0, "not_scanned": 0, "findings": 0,
            "issues": [{"resource_id": None, "operation": operation, "message": message}]}
