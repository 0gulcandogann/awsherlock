"""Pure resource-relationship projection, validation, and normalization."""

import re
from collections.abc import Iterable, Mapping
from dataclasses import replace

from awsherlock.collectors.common import CollectionResult
from awsherlock.models import (
    Relationship,
    RelationshipEvidence,
    RelationshipType,
    Resource,
    ResourceRef,
)


class RelationshipError(ValueError):
    """Relationship data cannot be normalized safely."""


_ARN = re.compile(
    r"^arn:(?P<partition>aws(?:-[a-z0-9-]+)?):(?P<service>[a-z0-9-]+):"
    r"(?P<region>[^:]*):(?P<account>[0-9]{12}):(?P<resource>[^\s]+)$"
)
_LAMBDA_RESOURCE = re.compile(r"function:(?P<resource_id>[A-Za-z0-9_-]{1,64})$")
_EC2_RESOURCE = re.compile(r"instance/(?P<resource_id>i-(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{17}))$")
_IAM_ROLE_RESOURCE = re.compile(r"role/(?P<path>[^\s]+/)?(?P<resource_id>[^/\s]+)$")


def _resources(services: Mapping[str, CollectionResult]) -> Iterable[Resource]:
    for collection in services.values():
        yield from collection.resources


def _resource_key(resource: Resource) -> tuple[str, str, str, str, str]:
    return (
        resource.account_id,
        resource.region or "",
        resource.service,
        resource.resource_type,
        resource.resource_id,
    )


def _reconcile_ref(current: ResourceRef | None, observed: ResourceRef) -> ResourceRef:
    if current is None:
        return observed
    if current.resource_arn is not None and observed.resource_arn is not None:
        if current.resource_arn != observed.resource_arn:
            raise RelationshipError("Conflicting resource ARNs for one logical relationship endpoint")
        return current
    return replace(current, resource_arn=current.resource_arn or observed.resource_arn)


def _validate_against_resources(reference: ResourceRef, resources: tuple[Resource, ...]) -> None:
    matching_arns = {
        resource.resource_arn
        for resource in resources
        if _resource_key(resource) == reference.logical_key and resource.resource_arn is not None
    }
    if len(matching_arns) > 1:
        raise RelationshipError("Collected resources have conflicting ARNs for one logical identity")
    for resource in resources:
        same_identity = _resource_key(resource) == reference.logical_key
        same_arn = reference.resource_arn is not None and resource.resource_arn == reference.resource_arn
        if same_arn and not same_identity:
            raise RelationshipError("Relationship resource ARN resolves to a different collected identity")
        if (same_identity and reference.resource_arn is not None and resource.resource_arn is not None
                and reference.resource_arn != resource.resource_arn):
            raise RelationshipError("Relationship resource ARN conflicts with the collected resource ARN")


def normalize_relationships(
    relationships: Iterable[Relationship],
    services: Mapping[str, CollectionResult],
) -> tuple[Relationship, ...]:
    """Merge positive duplicate edges and return a stable immutable sequence."""
    try:
        edges = tuple(relationships)
    except TypeError as error:
        raise RelationshipError("Relationships must be iterable") from error
    resources = tuple(_resources(services))
    references: dict[tuple[str, str, str, str, str], ResourceRef] = {}
    for edge in edges:
        if not isinstance(edge, Relationship):
            raise RelationshipError("Invalid relationship entry")
        for reference in (edge.source, edge.target):
            _validate_against_resources(reference, resources)
            references[reference.logical_key] = _reconcile_ref(references.get(reference.logical_key), reference)

    grouped: dict[
        tuple[tuple[str, str, str, str, str], str, tuple[str, str, str, str, str]],
        set[RelationshipEvidence],
    ] = {}
    for edge in edges:
        key = (edge.source.logical_key, edge.relationship_type.value, edge.target.logical_key)
        grouped.setdefault(key, set()).update(edge.evidence)

    normalized = []
    for (source_key, relationship_type, target_key), evidence in grouped.items():
        normalized.append(Relationship(
            source=references[source_key],
            relationship_type=RelationshipType(relationship_type),
            target=references[target_key],
            evidence=tuple(sorted(evidence, key=lambda item: item.sort_key)),
        ))
    return tuple(sorted(normalized, key=relationship_sort_key))


def relationship_sort_key(relationship: Relationship) -> tuple:
    return (
        relationship.source.logical_key,
        relationship.relationship_type.value,
        relationship.target.logical_key,
        relationship.source.resource_arn or "",
        relationship.target.resource_arn or "",
    )


def _parse_arn(value: object) -> re.Match[str] | None:
    return _ARN.fullmatch(value) if isinstance(value, str) else None


def _project_binding(role: Resource, binding: object) -> Relationship | None:
    if not isinstance(binding, dict) or set(binding) != {"service", "region", "resource_arn", "role_arn"}:
        return None
    service = binding.get("service")
    if service not in {"lambda", "ec2"}:
        return None
    region = binding.get("region")
    source_arn = binding.get("resource_arn")
    role_arn = binding.get("role_arn")
    source_match = _parse_arn(source_arn)
    role_match = _parse_arn(role_arn)
    if source_match is None or role_match is None or not isinstance(region, str) or not region:
        return None
    if (
        source_match["service"] != service
        or source_match["region"] != region
        or source_match["account"] != role.account_id
        or role_match["service"] != "iam"
        or role_match["region"] != ""
        or role_match["account"] != role.account_id
        or role_match["partition"] != source_match["partition"]
        or role.resource_arn != role_arn
    ):
        return None
    role_resource = _IAM_ROLE_RESOURCE.fullmatch(role_match["resource"])
    source_resource = (_LAMBDA_RESOURCE.fullmatch(source_match["resource"])
                       if service == "lambda" else _EC2_RESOURCE.fullmatch(source_match["resource"]))
    if role_resource is None or role_resource["resource_id"] != role.resource_id or source_resource is None:
        return None
    source = ResourceRef(
        service=service,
        resource_type="function" if service == "lambda" else "instance",
        account_id=source_match["account"],
        region=region,
        resource_id=source_resource["resource_id"],
        resource_arn=source_arn,
    )
    target = ResourceRef(
        service="iam",
        resource_type="role",
        account_id=role.account_id,
        region=None,
        resource_id=role.resource_id,
        resource_arn=role_arn,
    )
    return Relationship(
        source=source,
        relationship_type=RelationshipType.RUNS_AS,
        target=target,
        evidence=(RelationshipEvidence(service="iam", fact="identity_bindings", operation=None),),
    )


def project_relationships(services: Mapping[str, CollectionResult]) -> tuple[Relationship, ...]:
    """Project only Lambda/EC2 identity bindings already present in IAM facts."""
    edges = []
    iam = services.get("iam")
    if iam is None:
        return ()
    for role in iam.resources:
        if role.service != "iam" or role.resource_type != "role":
            continue
        bindings = role.data.get("identity_bindings")
        if not isinstance(bindings, list):
            continue
        for binding in bindings:
            edge = _project_binding(role, binding)
            if edge is not None:
                edges.append(edge)
    return normalize_relationships(edges, services)


def resource_ref_to_dict(reference: ResourceRef) -> dict:
    return {
        "service": reference.service,
        "resource_type": reference.resource_type,
        "account_id": reference.account_id,
        "region": reference.region,
        "resource_id": reference.resource_id,
        "resource_arn": reference.resource_arn,
    }


def relationship_to_dict(relationship: Relationship) -> dict:
    return {
        "source": resource_ref_to_dict(relationship.source),
        "type": relationship.relationship_type.value,
        "target": resource_ref_to_dict(relationship.target),
        "evidence": [{
            "service": item.service,
            "fact": item.fact,
            "operation": item.operation,
        } for item in relationship.evidence],
    }


def _resource_ref_from_dict(data: object) -> ResourceRef:
    if not isinstance(data, dict) or set(data) != {
        "service", "resource_type", "account_id", "region", "resource_id", "resource_arn"
    }:
        raise RelationshipError("Invalid relationship resource reference")
    return ResourceRef(**data)


def relationship_from_dict(data: object) -> Relationship:
    if not isinstance(data, dict) or set(data) != {"source", "type", "target", "evidence"}:
        raise RelationshipError("Invalid relationship object")
    raw_evidence = data["evidence"]
    if not isinstance(raw_evidence, list) or not raw_evidence:
        raise RelationshipError("Relationship evidence must be a non-empty list")
    evidence = []
    for item in raw_evidence:
        if not isinstance(item, dict) or set(item) != {"service", "fact", "operation"}:
            raise RelationshipError("Invalid relationship evidence object")
        evidence.append(RelationshipEvidence(**item))
    try:
        relationship_type = RelationshipType(data["type"])
    except (TypeError, ValueError):
        raise RelationshipError("Invalid relationship type") from None
    return Relationship(
        source=_resource_ref_from_dict(data["source"]),
        relationship_type=relationship_type,
        target=_resource_ref_from_dict(data["target"]),
        evidence=tuple(evidence),
    )
