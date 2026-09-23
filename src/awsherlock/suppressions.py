"""Exact, expiring local finding suppressions; findings remain in reports."""

import json
import re
from datetime import date, datetime, timezone
from pathlib import Path

from awsherlock.catalog import check_catalog
from awsherlock.evaluation import Report


class SuppressionError(ValueError):
    """Safe local suppression-file validation error."""


def _unique_pairs(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise SuppressionError("Duplicate JSON keys are not allowed")
        result[key] = value
    return result


def read_suppressions(path: Path) -> list[dict]:
    try:
        if path.stat().st_size > 1_000_000:
            raise SuppressionError("Suppression file exceeds 1 MB")
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, SuppressionError):
            raise
        raise SuppressionError("Could not read a valid suppression JSON file") from None
    if not isinstance(data, dict) or set(data) != {"schema_version", "suppressions"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise SuppressionError("Expected suppression schema version 1")
    entries = data["suppressions"]
    if not isinstance(entries, list) or len(entries) > 1000:
        raise SuppressionError("Suppressions must be a list of at most 1000 entries")
    valid_ids = {identifier for identifier, _, _ in check_catalog()}
    seen = set()
    validated = []
    for raw in entries:
        if not isinstance(raw, dict) or set(raw) != {"check_id", "account_id", "region", "resource_id", "owner", "reason", "expires_on"}:
            raise SuppressionError("Invalid suppression entry fields")
        check_id, account, region, resource = (raw[key] for key in ("check_id", "account_id", "region", "resource_id"))
        if not isinstance(check_id, str) or check_id not in valid_ids or not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account):
            raise SuppressionError("Invalid suppression check or account")
        if region is not None and (not isinstance(region, str) or not region.strip() or len(region) > 64):
            raise SuppressionError("Invalid suppression region")
        if not isinstance(resource, str) or not resource.strip() or len(resource) > 512:
            raise SuppressionError("Invalid suppression resource")
        for key in ("owner", "reason"):
            value = raw[key]
            if not isinstance(value, str) or not value.strip() or len(value) > 200:
                raise SuppressionError("Owner and reason must be non-empty text of at most 200 characters")
        expiry = raw["expires_on"]
        if not isinstance(expiry, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expiry):
            raise SuppressionError("Invalid suppression expiry date")
        try:
            date.fromisoformat(expiry)
        except ValueError:
            raise SuppressionError("Invalid suppression expiry date") from None
        identity = (check_id, account, region, resource)
        if identity in seen:
            raise SuppressionError("Duplicate suppression identity")
        seen.add(identity)
        validated.append(dict(raw))
    return validated


def apply_suppressions(report: Report, entries: list[dict], *, today: date | None = None) -> None:
    """Annotate exact matches without dropping findings or changing coverage."""
    current_day = today or datetime.now(timezone.utc).date()
    report.suppression_audit = []
    report.suppression_matches = {}
    for entry in entries:
        expired = date.fromisoformat(entry["expires_on"]) < current_day
        matches = [index for index, finding in enumerate(report.findings)
                   if finding.id == entry["check_id"] and finding.account_id == entry["account_id"]
                   and finding.region == entry["region"]
                   and entry["resource_id"] in {finding.resource_id, finding.resource_arn}]
        status = "EXPIRED" if expired else "APPLIED" if matches else "UNMATCHED"
        report.suppression_audit.append({**entry, "status": status, "matched_findings": len(matches)})
        if not expired:
            for index in matches:
                report.suppression_matches[index] = {"owner": entry["owner"], "reason": entry["reason"],
                                                     "expires_on": entry["expires_on"]}
