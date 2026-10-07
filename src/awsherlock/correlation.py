"""Pure deterministic models and indexes for investigation-lead correlation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Callable

from awsherlock.models import Finding, Relationship, RelationshipType, Resource, ResourceRef

if TYPE_CHECKING:
    from collections.abc import Mapping
    from awsherlock.snapshot import Snapshot


class CorrelationError(ValueError):
    """Correlation inputs conflict or cannot be normalized safely."""


class LeadPriority(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


PRIORITY_RANK = {
    LeadPriority.HIGH: 0,
    LeadPriority.MEDIUM: 1,
    LeadPriority.LOW: 2,
}


@dataclass(frozen=True, kw_only=True)
class FindingRef:
    check_id: str
    service: str
    account_id: str
    region: str | None
    resource_id: str
    resource_arn: str | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        for name in ("check_id", "service", "account_id", "resource_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise CorrelationError(f"{name} must be a non-empty string")
        if re.fullmatch(r"[0-9]{12}", self.account_id) is None:
            raise CorrelationError("account_id must contain 12 digits")
        if self.region is not None and (not isinstance(self.region, str) or not self.region.strip()):
            raise CorrelationError("region must be a non-empty string or None")
        if self.resource_arn is not None and (
            not isinstance(self.resource_arn, str) or not self.resource_arn.strip()
        ):
            raise CorrelationError("resource_arn must be a non-empty string or None")

    @property
    def logical_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.check_id,
            self.service,
            self.account_id,
            self.region or "",
            self.resource_id,
        )


@dataclass(frozen=True, kw_only=True)
class RelationshipRef:
    source: ResourceRef
    relationship_type: RelationshipType
    target: ResourceRef

    def __post_init__(self) -> None:
        if not isinstance(self.source, ResourceRef) or not isinstance(self.target, ResourceRef):
            raise CorrelationError("relationship references require ResourceRef endpoints")
        if not isinstance(self.relationship_type, RelationshipType):
            raise CorrelationError("relationship_type must be a RelationshipType")

    @property
    def logical_key(self) -> tuple:
        return (self.source.logical_key, self.relationship_type.value, self.target.logical_key)


@dataclass(frozen=True, kw_only=True)
class LeadStatement:
    code: str
    text: str = field(compare=False)

    def __post_init__(self) -> None:
        for name in ("code", "text"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise CorrelationError(f"{name} must be a non-empty string")


def _reconcile_resource(current: ResourceRef | None, observed: ResourceRef) -> ResourceRef:
    if not isinstance(observed, ResourceRef):
        raise CorrelationError("lead resources must be ResourceRef values")
    if current is None:
        return observed
    if current.resource_arn and observed.resource_arn and current.resource_arn != observed.resource_arn:
        raise CorrelationError("Conflicting resource ARNs for one logical lead resource")
    return replace(current, resource_arn=current.resource_arn or observed.resource_arn)


def _normalize_resources(resources: Iterable[ResourceRef]) -> tuple[ResourceRef, ...]:
    reconciled: dict[tuple[str, str, str, str, str], ResourceRef] = {}
    for item in resources:
        if not isinstance(item, ResourceRef):
            raise CorrelationError("lead resources must be ResourceRef values")
        reconciled[item.logical_key] = _reconcile_resource(reconciled.get(item.logical_key), item)
    return tuple(sorted(reconciled.values(), key=lambda item: (item.logical_key, item.resource_arn or "")))


def _reconcile_finding(current: FindingRef | None, observed: FindingRef) -> FindingRef:
    if not isinstance(observed, FindingRef):
        raise CorrelationError("finding_refs must contain FindingRef values")
    if current is None:
        return observed
    if current.resource_arn and observed.resource_arn and current.resource_arn != observed.resource_arn:
        raise CorrelationError("Conflicting resource ARNs for one logical finding")
    return replace(current, resource_arn=current.resource_arn or observed.resource_arn)


def _normalize_findings(findings: Iterable[FindingRef]) -> tuple[FindingRef, ...]:
    reconciled: dict[tuple[str, str, str, str, str], FindingRef] = {}
    for item in findings:
        if not isinstance(item, FindingRef):
            raise CorrelationError("finding_refs must contain FindingRef values")
        reconciled[item.logical_key] = _reconcile_finding(reconciled.get(item.logical_key), item)
    return tuple(sorted(reconciled.values(), key=lambda item: (item.logical_key, item.resource_arn or "")))


def _normalize_relationships(relationships: Iterable[RelationshipRef]) -> tuple[RelationshipRef, ...]:
    grouped: dict[tuple, RelationshipRef] = {}
    for item in relationships:
        if not isinstance(item, RelationshipRef):
            raise CorrelationError("relationship_refs must contain RelationshipRef values")
        current = grouped.get(item.logical_key)
        if current is None:
            grouped[item.logical_key] = item
            continue
        grouped[item.logical_key] = RelationshipRef(
            source=_reconcile_resource(current.source, item.source),
            relationship_type=item.relationship_type,
            target=_reconcile_resource(current.target, item.target),
        )
    return tuple(sorted(grouped.values(), key=lambda item: (
        item.source.logical_key,
        item.relationship_type.value,
        item.target.logical_key,
        item.source.resource_arn or "",
        item.target.resource_arn or "",
    )))


def _normalize_statements(statements: Iterable[LeadStatement]) -> tuple[LeadStatement, ...]:
    by_code: dict[str, LeadStatement] = {}
    for item in statements:
        if not isinstance(item, LeadStatement):
            raise CorrelationError("lead statements must be LeadStatement values")
        current = by_code.get(item.code)
        if current is not None and current.text != item.text:
            raise CorrelationError("Conflicting lead statement text for one code")
        by_code[item.code] = item
    return tuple(by_code[code] for code in sorted(by_code))


@dataclass(frozen=True, kw_only=True)
class Lead:
    pattern_id: str
    subjects: tuple[ResourceRef, ...]
    title: str = field(compare=False)
    priority: LeadPriority = field(compare=False)
    related_resources: tuple[ResourceRef, ...] = field(default=(), compare=False)
    finding_refs: tuple[FindingRef, ...] = field(default=(), compare=False)
    relationship_refs: tuple[RelationshipRef, ...] = field(default=(), compare=False)
    observed: tuple[LeadStatement, ...] = field(default=(), compare=False)
    unknown: tuple[LeadStatement, ...] = field(default=(), compare=False)
    not_proven: tuple[LeadStatement, ...] = field(default=(), compare=False)
    why_it_matters: str = field(compare=False)
    next_step: str = field(compare=False)
    lead_id: str = field(init=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.pattern_id, str) or not self.pattern_id.strip():
            raise CorrelationError("pattern_id must be a non-empty string")
        if not isinstance(self.priority, LeadPriority):
            raise CorrelationError("priority must be a LeadPriority")
        for name in ("title", "why_it_matters", "next_step"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise CorrelationError(f"{name} must be a non-empty string")
        subjects = _normalize_resources(self.subjects)
        if not subjects:
            raise CorrelationError("Lead subjects must not be empty")
        object.__setattr__(self, "subjects", subjects)
        object.__setattr__(self, "related_resources", _normalize_resources(self.related_resources))
        object.__setattr__(self, "finding_refs", _normalize_findings(self.finding_refs))
        object.__setattr__(self, "relationship_refs", _normalize_relationships(self.relationship_refs))
        object.__setattr__(self, "observed", _normalize_statements(self.observed))
        object.__setattr__(self, "unknown", _normalize_statements(self.unknown))
        object.__setattr__(self, "not_proven", _normalize_statements(self.not_proven))
        identity = {
            "pattern_id": self.pattern_id,
            "subjects": [list(item.logical_key) for item in subjects],
        }
        digest = hashlib.sha256(json.dumps(
            identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")).hexdigest()
        object.__setattr__(self, "lead_id", f"{self.pattern_id}:{digest}")


def lead_identity_key(lead: Lead) -> tuple[str, tuple[tuple[str, str, str, str, str], ...]]:
    return (lead.pattern_id, tuple(item.logical_key for item in lead.subjects))


def merge_leads(candidates: Iterable[Lead]) -> tuple[Lead, ...]:
    """Merge candidates by explicit logical identity without losing support."""
    grouped: dict[tuple, Lead] = {}
    for candidate in candidates:
        if not isinstance(candidate, Lead):
            raise CorrelationError("Correlation rules must return Lead values")
        key = lead_identity_key(candidate)
        current = grouped.get(key)
        if current is None:
            grouped[key] = candidate
            continue
        static = ("title", "priority", "why_it_matters", "next_step")
        if any(getattr(current, name) != getattr(candidate, name) for name in static):
            raise CorrelationError("Conflicting static metadata for one logical lead")
        grouped[key] = replace(
            current,
            subjects=current.subjects + candidate.subjects,
            related_resources=current.related_resources + candidate.related_resources,
            finding_refs=current.finding_refs + candidate.finding_refs,
            relationship_refs=current.relationship_refs + candidate.relationship_refs,
            observed=current.observed + candidate.observed,
            unknown=current.unknown + candidate.unknown,
            not_proven=current.not_proven + candidate.not_proven,
        )
    return tuple(sorted(grouped.values(), key=lambda item: (
        PRIORITY_RANK[item.priority], item.pattern_id, item.lead_id,
    )))


def resource_ref_to_dict(reference: ResourceRef) -> dict:
    return {
        "service": reference.service,
        "resource_type": reference.resource_type,
        "account_id": reference.account_id,
        "region": reference.region,
        "resource_id": reference.resource_id,
        "resource_arn": reference.resource_arn,
    }


def finding_ref_to_dict(reference: FindingRef) -> dict:
    return {
        "check_id": reference.check_id,
        "service": reference.service,
        "account_id": reference.account_id,
        "region": reference.region,
        "resource_id": reference.resource_id,
        "resource_arn": reference.resource_arn,
    }


def relationship_ref_to_dict(reference: RelationshipRef) -> dict:
    return {
        "source": resource_ref_to_dict(reference.source),
        "type": reference.relationship_type.value,
        "target": resource_ref_to_dict(reference.target),
    }


def lead_to_dict(lead: Lead) -> dict:
    return {
        "lead_id": lead.lead_id,
        "pattern_id": lead.pattern_id,
        "title": lead.title,
        "priority": lead.priority.value,
        "subjects": [resource_ref_to_dict(item) for item in lead.subjects],
        "related_resources": [resource_ref_to_dict(item) for item in lead.related_resources],
        "findings": [finding_ref_to_dict(item) for item in lead.finding_refs],
        "relationships": [relationship_ref_to_dict(item) for item in lead.relationship_refs],
        "observed": [{"code": item.code, "text": item.text} for item in lead.observed],
        "unknown": [{"code": item.code, "text": item.text} for item in lead.unknown],
        "not_proven": [{"code": item.code, "text": item.text} for item in lead.not_proven],
        "why_it_matters": lead.why_it_matters,
        "next_step": lead.next_step,
    }


def finding_ref(finding: Finding) -> FindingRef:
    return FindingRef(
        check_id=finding.id,
        service=finding.service,
        account_id=finding.account_id,
        region=finding.region,
        resource_id=finding.resource_id,
        resource_arn=finding.resource_arn,
    )


def relationship_ref(relationship: Relationship) -> RelationshipRef:
    return RelationshipRef(
        source=relationship.source,
        relationship_type=relationship.relationship_type,
        target=relationship.target,
    )


def resource_ref(resource: Resource) -> ResourceRef:
    return ResourceRef(
        service=resource.service,
        resource_type=resource.resource_type,
        account_id=resource.account_id,
        region=resource.region,
        resource_id=resource.resource_id,
        resource_arn=resource.resource_arn,
    )


FindingResourceKey = tuple[str, str, str, str]


def finding_resource_key(finding: Finding) -> FindingResourceKey:
    return (finding.account_id, finding.region or "", finding.service, finding.resource_id)


def ref_finding_key(reference: ResourceRef) -> FindingResourceKey:
    return (reference.account_id, reference.region or "", reference.service, reference.resource_id)


@dataclass(frozen=True, kw_only=True)
class CorrelationContext:
    """Small immutable lookup layer over one evaluated snapshot."""

    snapshot: Snapshot
    findings: tuple[Finding, ...]
    resources_by_key: Mapping[FindingResourceKey, tuple[Resource, ...]]
    findings_by_check: Mapping[str, tuple[Finding, ...]]
    findings_by_resource: Mapping[FindingResourceKey, tuple[Finding, ...]]
    relationships_from: Mapping[tuple[str, str, str, str, str], tuple[Relationship, ...]]
    relationships_to: Mapping[tuple[str, str, str, str, str], tuple[Relationship, ...]]
    coverage_by_service: Mapping[str, Mapping[str, object]]

    def resource_for(self, key: FindingResourceKey, *, resource_type: str,
                     resource_arn: str | None = None) -> Resource | None:
        matches = tuple(item for item in self.resources_by_key.get(key, ())
                        if item.resource_type == resource_type
                        and (resource_arn is None or item.resource_arn == resource_arn))
        return matches[0] if len(matches) == 1 else None


def build_correlation_context(
    snapshot: Snapshot,
    findings: Iterable[Finding],
    coverage: Iterable[dict],
) -> CorrelationContext:
    resources: dict[FindingResourceKey, list[Resource]] = {}
    for collection in snapshot.services.values():
        for item in collection.resources:
            key = (item.account_id, item.region or "", item.service, item.resource_id)
            if item not in resources.setdefault(key, []):
                resources[key].append(item)
    finding_values = tuple(findings)
    by_check: dict[str, list[Finding]] = {}
    by_resource: dict[FindingResourceKey, list[Finding]] = {}
    for item in finding_values:
        by_check.setdefault(item.id, []).append(item)
        by_resource.setdefault(finding_resource_key(item), []).append(item)
    from_index: dict[tuple[str, str, str, str, str], list[Relationship]] = {}
    to_index: dict[tuple[str, str, str, str, str], list[Relationship]] = {}
    for item in snapshot.relationships:
        from_index.setdefault(item.source.logical_key, []).append(item)
        to_index.setdefault(item.target.logical_key, []).append(item)
    finding_sort = lambda item: (*finding_resource_key(item), item.id, item.resource_arn or "")
    relationship_sort = lambda item: (
        item.source.logical_key, item.relationship_type.value, item.target.logical_key,
        item.source.resource_arn or "", item.target.resource_arn or "",
    )
    return CorrelationContext(
        snapshot=snapshot,
        findings=finding_values,
        resources_by_key=MappingProxyType({
            key: tuple(sorted(value, key=lambda item: (item.resource_type, item.resource_arn or "")))
            for key, value in resources.items()
        }),
        findings_by_check=MappingProxyType({
            key: tuple(sorted(value, key=finding_sort)) for key, value in by_check.items()
        }),
        findings_by_resource=MappingProxyType({
            key: tuple(sorted(value, key=finding_sort)) for key, value in by_resource.items()
        }),
        relationships_from=MappingProxyType({
            key: tuple(sorted(value, key=relationship_sort)) for key, value in from_index.items()
        }),
        relationships_to=MappingProxyType({
            key: tuple(sorted(value, key=relationship_sort)) for key, value in to_index.items()
        }),
        coverage_by_service=MappingProxyType({
            row["service"]: MappingProxyType(dict(row)) for row in coverage
        }),
    )


CorrelationFunction = Callable[[CorrelationContext], tuple[Lead, ...]]


@dataclass(frozen=True, kw_only=True)
class CorrelationRule:
    pattern_id: str
    title: str
    priority: LeadPriority
    requires_relationships: bool
    correlate: CorrelationFunction

    def __post_init__(self) -> None:
        if not isinstance(self.pattern_id, str) or not self.pattern_id.strip():
            raise CorrelationError("Correlation rule pattern_id must be a non-empty string")
        if not isinstance(self.title, str) or not self.title.strip():
            raise CorrelationError("Correlation rule title must be a non-empty string")
        if (not isinstance(self.priority, LeadPriority)
                or type(self.requires_relationships) is not bool or not callable(self.correlate)):
            raise CorrelationError("Invalid correlation rule metadata")


def validate_correlation_rules(rules: tuple[CorrelationRule, ...]) -> None:
    identifiers = [rule.pattern_id for rule in rules]
    if len(identifiers) != len(set(identifiers)):
        raise CorrelationError("Duplicate correlation rule pattern ID")
