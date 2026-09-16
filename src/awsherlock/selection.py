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
