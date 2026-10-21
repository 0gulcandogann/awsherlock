"""Immutable derived investigation contracts; no AWS clients or raw payloads."""

from dataclasses import asdict, dataclass
import hashlib
import json
import re

from awsherlock.correlation import (
    FindingRef,
    RelationshipRef,
    finding_ref_to_dict,
    relationship_ref_to_dict,
    resource_ref_to_dict,
)
from awsherlock.models import ResourceRef


def canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def stable_id(kind: str, identity: object) -> str:
    return kind + ":" + hashlib.sha256(canonical(identity).encode("ascii")).hexdigest()


@dataclass(frozen=True, kw_only=True)
class EvidenceRef:
    kind: str
    id: str

    def __post_init__(self) -> None:
        if self.kind not in {"FINDING", "RELATIONSHIP", "COVERAGE"}:
            raise ValueError("Unsupported evidence reference kind")
        if (
            not isinstance(self.id, str)
            or re.fullmatch(self.kind.lower() + r":[0-9a-f]{64}", self.id) is None
        ):
            raise ValueError("Evidence reference identity does not match its kind")

    @classmethod
    def from_reference(cls, reference: FindingRef | RelationshipRef) -> "EvidenceRef":
        if isinstance(reference, FindingRef):
            return cls(kind="FINDING", id=stable_id("finding", reference.logical_key))
        if isinstance(reference, RelationshipRef):
            return cls(kind="RELATIONSHIP", id=stable_id("relationship", reference.logical_key))
        raise ValueError("Unsupported evidence reference")


@dataclass(frozen=True, kw_only=True)
class CoverageGate:
    code: str
    account_id: str
    region: str | None
    service: str | None = None
    status: str = "UNKNOWN"
    reason_code: str | None = None
    operation: str | None = None
    resource_id: str | None = None

    @property
    def id(self) -> str:
        return stable_id("coverage", asdict(self))

    def to_dict(self) -> dict:
        return {"id": self.id, **asdict(self)}


@dataclass(frozen=True, kw_only=True)
class InvestigationCondition:
    code: str
    text: str
    evidence: tuple[EvidenceRef, ...] = ()
    assumptions: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class PriorityFactor:
    code: str
    points: int
    explanation: str
    evidence: tuple[EvidenceRef, ...]


@dataclass(frozen=True, kw_only=True)
class InvestigationAction:
    code: str
    text: str


@dataclass(frozen=True, kw_only=True)
class Investigation:
    id: str
    lead_id: str
    pattern_id: str
    title: str
    account_id: str
    region: str | None
    resources: tuple[ResourceRef, ...]
    supporting_findings: tuple[FindingRef, ...]
    supporting_relationships: tuple[RelationshipRef, ...]
    observed: tuple[InvestigationCondition, ...]
    inferred: tuple[InvestigationCondition, ...]
    unknown: tuple[InvestigationCondition, ...]
    coverage_gaps: tuple[CoverageGate, ...]
    priority: str
    priority_status: str
    priority_score: int | None
    priority_factors: tuple[PriorityFactor, ...]
    priority_explanation: str
    explanation: str
    recommended_actions: tuple[InvestigationAction, ...]

    def to_dict(self) -> dict:
        result = asdict(self)
        result["resources"] = [resource_ref_to_dict(item) for item in self.resources]
        result["supporting_findings"] = [
            {"id": EvidenceRef.from_reference(item).id, "reference": finding_ref_to_dict(item)}
            for item in self.supporting_findings
        ]
        result["supporting_relationships"] = [
            {"id": EvidenceRef.from_reference(item).id, "reference": relationship_ref_to_dict(item)}
            for item in self.supporting_relationships
        ]
        result["coverage_gaps"] = [item.to_dict() for item in self.coverage_gaps]
        return json.loads(canonical(result))


@dataclass(frozen=True, kw_only=True)
class InvestigationResult:
    account_id: str
    region: str | None
    investigations: tuple[Investigation, ...]
    coverage_gaps: tuple[CoverageGate, ...]
    incomplete: bool

    def to_dict(self) -> dict:
        return {
            "kind": "contextual-investigations",
            "schema_version": 1,
            "priority_policy_version": 1,
            "account_id": self.account_id,
            "region": self.region,
            "incomplete": self.incomplete,
            "investigations": [item.to_dict() for item in self.investigations],
            "coverage_gaps": [item.to_dict() for item in self.coverage_gaps],
            "limitations": "Configuration indicators do not prove effective access, impact, "
            "reachability or exploitability. Missing investigations do not establish safety. "
            "Asset criticality and exhaustive relationship inventory are unknown.",
        }
