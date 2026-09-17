"""Validate explicit target selectors without credentials or network requests."""

import re

from awsherlock.catalog import check_catalog


def parse_check_selection(value: str | None) -> list[str] | None:
    if value is None:
        return None
    selected = list(dict.fromkeys(part.strip().upper() for part in value.split(",")))
    known = {identifier for identifier, _, _ in check_catalog()}
    if not selected or any(identifier not in known for identifier in selected):
        raise ValueError("Use comma-separated registered check IDs; see awsherlock --list-checks.")
    return selected


def parse_account_selection(value: str | None) -> list[str] | None:
    if value is None:
        return None
    selected = list(dict.fromkeys(part.strip() for part in value.split(",")))
    if not selected or any(not re.fullmatch(r"[0-9]{12}", account) for account in selected):
        raise ValueError("Use comma-separated 12-digit account IDs.")
    return selected


def parse_ou_selection(value: str | None) -> list[str] | None:
    if value is None:
        return None
    selected = list(dict.fromkeys(part.strip() for part in value.split(",")))
    if not selected or any(not re.fullmatch(r"ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}", identifier) for identifier in selected):
        raise ValueError("Use comma-separated organizational unit IDs (ou-...).")
    return selected


def parse_resource_selection(value: str | None) -> list[str] | None:
    if value is None:
        return None
    selected = list(dict.fromkeys(part.strip() for part in value.split(",")))
    if not selected or any(not item or len(item) > 2048 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in item)
                           or "*" in item or "?" in item for item in selected):
        raise ValueError("Use comma-separated exact resource IDs or ARNs; patterns are not supported.")
    return selected
