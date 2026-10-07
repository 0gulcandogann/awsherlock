"""Normalized data shared by collection, evaluation, and reporting.

These models contain facts and metadata only, never SDK sessions. Callers must
exclude credentials and secret values when normalizing collected facts.
"""

import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import TypeAlias

JSONValue: TypeAlias = str | int | float | bool | None | list["JSONValue"] | dict[str, "JSONValue"]


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CoverageStatus(StrEnum):
    """Evaluation states from SPEC.md; missing permissions must never be PASS."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    NOT_SCANNED = "NOT_SCANNED"
    PARTIAL = "PARTIAL"


class RelationshipType(StrEnum):
    RUNS_AS = "RUNS_AS"
    INVOKES = "INVOKES"
    USES = "USES"


def _text(name: str, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _location(account_id: str, region: str | None) -> None:
    if not isinstance(account_id, str) or not re.fullmatch(r"[0-9]{12}", account_id):
        raise ValueError("account_id must contain 12 digits")
    if region is not None:
        _text("region", region)


def _identifier(name: str, value: object) -> None:
    _text(name, value)
    if len(value) > 64 or re.fullmatch(r"[a-z0-9][a-z0-9_-]*", value) is None:
        raise ValueError(f"{name} must be a normalized identifier")


def _json_value(value: object) -> None:
    if value is None or type(value) in (str, int, bool):
        return
    if type(value) is float and math.isfinite(value):
        return
    if isinstance(value, list):
        for item in value:
            _json_value(item)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for item in value.values():
            _json_value(item)
        return
    raise ValueError("Facts and evidence must contain only JSON-compatible values")


@dataclass(frozen=True, kw_only=True)
class ScanMetadata:
    scan_id: str
    started_at: datetime
    account_id: str
    region: str | None
    version: str

    def __post_init__(self) -> None:
        _text("scan_id", self.scan_id)
        _text("version", self.version)
        _location(self.account_id, self.region)
        if not isinstance(self.started_at, datetime) or self.started_at.utcoffset() is None:
            raise ValueError("started_at must be a timezone-aware datetime")


@dataclass(frozen=True, kw_only=True)
class Resource:
    """Normalized facts; None region/ARN means unavailable or not applicable."""

    service: str
    resource_type: str
    account_id: str
    region: str | None
    resource_id: str
    resource_arn: str | None
    data: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _location(self.account_id, self.region)
        for name in ("service", "resource_type", "resource_id"):
            _text(name, getattr(self, name))
        if self.resource_arn is not None:
            _text("resource_arn", self.resource_arn)
        if not isinstance(self.data, dict):
            raise ValueError("data must be a dictionary")
        _json_value(self.data)


@dataclass(frozen=True, kw_only=True)
class ResourceRef:
    """Stable resource identity; ARN is an optional locator, not identity."""

    service: str
    resource_type: str
    account_id: str
    region: str | None
    resource_id: str
    resource_arn: str | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        _identifier("service", self.service)
        _identifier("resource_type", self.resource_type)
        _location(self.account_id, self.region)
        _text("resource_id", self.resource_id)
        if self.resource_arn is not None:
            _text("resource_arn", self.resource_arn)

    @property
    def logical_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.account_id,
            self.region or "",
            self.service,
            self.resource_type,
            self.resource_id,
        )


@dataclass(frozen=True, kw_only=True)
class RelationshipEvidence:
    service: str
    fact: str
    operation: str | None = None

    def __post_init__(self) -> None:
        _identifier("service", self.service)
        _identifier("fact", self.fact)
        if self.operation is not None:
            _text("operation", self.operation)

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return (self.service, self.fact, self.operation or "")


@dataclass(frozen=True, kw_only=True)
class Relationship:
    source: ResourceRef
    relationship_type: RelationshipType
    target: ResourceRef
    evidence: tuple[RelationshipEvidence, ...] = field(compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.source, ResourceRef) or not isinstance(self.target, ResourceRef):
            raise ValueError("relationship endpoints must be ResourceRef values")
        if not isinstance(self.relationship_type, RelationshipType):
            raise ValueError("relationship_type must be a RelationshipType value")
        if not isinstance(self.evidence, tuple) or not self.evidence:
            raise ValueError("relationship evidence must be a non-empty tuple")
        if any(not isinstance(item, RelationshipEvidence) for item in self.evidence):
            raise ValueError("relationship evidence contains an invalid entry")


@dataclass(frozen=True, kw_only=True)
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    service: str
    account_id: str
    region: str | None
    resource_id: str
    resource_arn: str | None
    evidence: dict[str, JSONValue]
    risk: str
    remediation: str
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _location(self.account_id, self.region)
        for name in ("id", "title", "description", "service", "resource_id", "risk", "remediation"):
            _text(name, getattr(self, name))
        if not isinstance(self.severity, Severity):
            raise ValueError("severity must be a Severity value")
        if self.resource_arn is not None:
            _text("resource_arn", self.resource_arn)
        if not isinstance(self.evidence, dict):
            raise ValueError("evidence must be a dictionary")
        _json_value(self.evidence)
        if not isinstance(self.references, list):
            raise ValueError("references must be a list of strings")
        for reference in self.references:
            _text("reference", reference)

    def to_dict(self) -> dict[str, JSONValue]:
        """Return detached JSON-compatible data, without writing a report."""
        self.__post_init__()  # Nested facts/references may have been mutated.
        result = asdict(self)
        result["severity"] = self.severity.value
        return result
