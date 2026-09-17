"""Explicit, credential-free identity governance configuration and declarations."""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

IDENTITY_ARN = re.compile(r"arn:([a-z0-9-]+):iam::([0-9]{12}):(role|user)/[^\s*?]+")


@dataclass(frozen=True)
class IdentityOptions:
    inventory: dict | None = field(default=None, repr=False)
    events: bool = False
    ai_services: bool = False
    analyzers: bool = False
    days: int = 30
    max_pages: int = 20
    max_seconds: int = 60
    regions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.inventory is not None:
            validate_inventory(self.inventory)
        if any(type(value) is not bool for value in (self.events, self.ai_services, self.analyzers)):
            raise ValueError("Invalid identity evidence switches")
        for value, maximum in ((self.days, 90), (self.max_pages, 1000), (self.max_seconds, 3600)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("Invalid identity evidence budget")
        if not isinstance(self.regions, tuple) or any(not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", region) for region in self.regions):
            raise ValueError("Invalid identity evidence regions")


def _pairs(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate inventory keys")
        result[key] = value
    return result


def validate_inventory(data: object) -> dict:
    """An explicit complete scope is needed before absence means unregistered."""
    if not isinstance(data, dict) or set(data) != {"schema_version", "accounts", "complete", "identities"}:
        raise ValueError("Invalid identity inventory")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1 or type(data["complete"]) is not bool:
        raise ValueError("Invalid identity inventory")
    if not isinstance(data["accounts"], list) or not data["accounts"] or any(
        not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account) for account in data["accounts"]
    ) or len(set(data["accounts"])) != len(data["accounts"]):
        raise ValueError("Invalid inventory account scope")
    if not isinstance(data["identities"], list):
        raise ValueError("Invalid identity inventory")
    seen = set()
    for entry in data["identities"]:
        required = {"arn", "kind", "owner", "purpose", "allowed_principals", "shared"}
        optional = {"external_id_required", "source_identity_required"}
        if not isinstance(entry, dict) or not required <= set(entry) or not set(entry) <= required | optional:
            raise ValueError("Invalid identity declaration")
        match = IDENTITY_ARN.fullmatch(entry["arn"]) if isinstance(entry["arn"], str) else None
        if match is None or match[2] not in data["accounts"] or entry["arn"] in seen:
            raise ValueError("Invalid identity declaration ARN/scope")
        seen.add(entry["arn"])
        if entry["kind"] not in {"ai", "workload", "human", "unknown"} or type(entry["shared"]) is not bool:
            raise ValueError("Invalid identity declaration kind")
        if any(type(entry.get(key, False)) is not bool for key in optional):
            raise ValueError("Invalid declared trust controls")
        for key in ("owner", "purpose"):
            if not isinstance(entry[key], str) or len(entry[key]) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in entry[key]):
                raise ValueError("Invalid declaration metadata")
        principals = entry["allowed_principals"]
        if not isinstance(principals, list) or any(not isinstance(p, str) or not p or any(c.isspace() for c in p)
                                                 or "*" in p or "?" in p for p in principals):
            raise ValueError("Approval principals must be exact")
        if any(not re.fullmatch(r"(?:[0-9]{12}|[a-z0-9.-]+\.amazonaws\.com(?:\.cn)?|arn:[a-z0-9-]+:iam::[0-9]{12}:(?:root|(?:role|user|oidc-provider|saml-provider)/[^\s*?]+))", p) for p in principals):
            raise ValueError("Invalid approval principal")
    return data


def read_inventory(path: Path) -> dict:
    try:
        if path.stat().st_size > 2_000_000:
            raise ValueError()
        return validate_inventory(json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise ValueError("Invalid identity inventory; use the documented version-1 schema.") from None


def approval_fact(account_id: str, arn: str, inventory: dict | None) -> dict:
    entry = next((item for item in inventory["identities"] if item["arn"] == arn), None) if inventory else None
    scoped = inventory is not None and account_id in inventory["accounts"] and isinstance(arn, str) and IDENTITY_ARN.fullmatch(arn) is not None
    return {"status": "registered" if scoped and entry else ("unregistered" if scoped and inventory["complete"] else "unknown"),
            "declared_kind": entry["kind"] if entry else "unknown",
            "owner": bool(entry and entry["owner"].strip()), "purpose": bool(entry and entry["purpose"].strip()),
            "allowed_principals": list(entry["allowed_principals"]) if entry else [], "shared": bool(entry and entry["shared"]),
            "external_id_required": bool(entry and entry.get("external_id_required", False)),
            "source_identity_required": bool(entry and entry.get("source_identity_required", False))}
