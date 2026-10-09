from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from awsherlock.collectors.common import CollectionResult
from awsherlock.diff import compare_snapshots
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.history import finding_history
from awsherlock.models import (
    Relationship,
    RelationshipEvidence,
    RelationshipType,
    Resource,
    ResourceRef,
    ScanMetadata,
)
from awsherlock.relationships import RelationshipError, normalize_relationships, project_relationships
from awsherlock.snapshot import Snapshot, SnapshotError, capture_snapshot, snapshot_from_dict


ACCOUNT = "123456789012"
OTHER_ACCOUNT = "999999999999"
REGION = "eu-west-1"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/service-role/worker-role"
LAMBDA_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:worker"
EC2_ARN = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0"


def metadata() -> ScanMetadata:
    return ScanMetadata(
        scan_id="relationships",
        started_at=datetime(2026, 10, 7, tzinfo=timezone.utc),
        account_id=ACCOUNT,
        region=REGION,
        version="test",
    )


def ref(
    service: str = "lambda",
    resource_type: str = "function",
    account_id: str = ACCOUNT,
    region: str | None = REGION,
    resource_id: str = "worker",
    resource_arn: str | None = LAMBDA_ARN,
) -> ResourceRef:
    return ResourceRef(
        service=service,
        resource_type=resource_type,
        account_id=account_id,
        region=region,
        resource_id=resource_id,
        resource_arn=resource_arn,
    )


def role_ref(resource_arn: str | None = ROLE_ARN) -> ResourceRef:
    return ref("iam", "role", ACCOUNT, None, "worker-role", resource_arn)


def evidence(
    service: str = "iam",
    fact: str = "identity_bindings",
    operation: str | None = None,
) -> RelationshipEvidence:
    return RelationshipEvidence(service=service, fact=fact, operation=operation)


def relationship(
    source: ResourceRef | None = None,
    target: ResourceRef | None = None,
    entries: tuple[RelationshipEvidence, ...] | None = None,
) -> Relationship:
    return Relationship(
        source=source or ref(),
        relationship_type=RelationshipType.RUNS_AS,
        target=target or role_ref(),
        evidence=entries or (evidence(),),
    )


def services_with_s3() -> dict[str, CollectionResult]:
    resource = Resource(
        service="s3",
        resource_type="bucket",
        account_id=ACCOUNT,
        region=REGION,
        resource_id="evidence-bucket",
        resource_arn=None,
        data={"public_access_block": None, "account_public_access_block": None},
    )
    return {"s3": CollectionResult([resource], [])}


def iam_services(bindings: list[dict]) -> dict[str, CollectionResult]:
    role = Resource(
        service="iam",
        resource_type="role",
        account_id=ACCOUNT,
        region=None,
        resource_id="worker-role",
        resource_arn=ROLE_ARN,
        data={"identity_bindings": bindings},
    )
    return {"iam": CollectionResult([role], [])}


def test_relationship_models_are_frozen_and_use_logical_identity():
    first = ref(resource_arn=None)
    located = ref(resource_arn=LAMBDA_ARN)
    assert first == located
    assert hash(first) == hash(located)
    edge = relationship(source=first)
    duplicate = relationship(source=located, entries=(evidence(operation="FutureOperation"),))
    assert edge == duplicate
    with pytest.raises((AttributeError, TypeError)):
        edge.source = role_ref()


@pytest.mark.parametrize("relationship_type", list(RelationshipType))
def test_relationship_vocabulary_is_exact(relationship_type):
    assert relationship_type.value in {"RUNS_AS", "INVOKES", "USES"}


def test_relationship_vocabulary_has_no_action_group():
    assert {item.value for item in RelationshipType} == {"RUNS_AS", "INVOKES", "USES"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("service", ""),
        ("service", "Bad Service"),
        ("resource_type", ""),
        ("resource_type", "Bad Type"),
        ("account_id", "123"),
        ("region", ""),
        ("resource_id", ""),
        ("resource_arn", ""),
    ],
)
def test_resource_ref_rejects_malformed_fields(field, value):
    values = {
        "service": "future-service",
        "resource_type": "future_type",
        "account_id": ACCOUNT,
        "region": REGION,
        "resource_id": "future-resource",
        "resource_arn": None,
    }
    values[field] = value
    with pytest.raises(ValueError):
        ResourceRef(**values)


def test_resource_refs_support_arnless_global_regional_and_cross_account_endpoints():
    global_source = ref("iam", "role", ACCOUNT, None, "worker-role", None)
    regional_target = ref("future-service", "future_type", OTHER_ACCOUNT, "us-east-2", "target", None)
    edge = Relationship(
        source=global_source,
        relationship_type=RelationshipType.USES,
        target=regional_target,
        evidence=(evidence("future-service", "component_binding"),),
    )
    normalized = normalize_relationships((edge,), services_with_s3())
    assert normalized == (edge,)


def test_relationship_requires_evidence():
    with pytest.raises(ValueError, match="evidence"):
        Relationship(
            source=ref(),
            relationship_type=RelationshipType.RUNS_AS,
            target=role_ref(),
            evidence=(),
        )


@pytest.mark.parametrize(
    "values",
    [
        {"service": "", "fact": "identity_bindings"},
        {"service": 1, "fact": "identity_bindings"},
        {"service": "iam", "fact": ""},
        {"service": "iam", "fact": 1},
        {"service": "iam", "fact": "identity_bindings", "operation": ""},
        {"service": "iam", "fact": "identity_bindings", "operation": 1},
    ],
)
def test_relationship_evidence_rejects_empty_fields(values):
    with pytest.raises(ValueError):
        RelationshipEvidence(**values)


def test_normalization_merges_duplicate_edges_and_evidence_deterministically():
    first = relationship(
        source=ref(resource_arn=None),
        entries=(evidence("z-service", "z-fact", "ZOperation"), evidence()),
    )
    second = relationship(
        source=ref(resource_arn=LAMBDA_ARN),
        entries=(evidence(), evidence("a-service", "a-fact")),
    )
    normalized = normalize_relationships((first, second), services_with_s3())
    assert len(normalized) == 1
    assert normalized[0].source.resource_arn == LAMBDA_ARN
    assert normalized[0].evidence == (
        evidence("a-service", "a-fact"),
        evidence(),
        evidence("z-service", "z-fact", "ZOperation"),
    )


def test_normalization_rejects_conflicting_non_null_arns():
    conflicting = "arn:aws:lambda:eu-west-1:123456789012:function:different-locator"
    with pytest.raises(RelationshipError, match="ARN"):
        normalize_relationships(
            (relationship(source=ref(resource_arn=LAMBDA_ARN)), relationship(source=ref(resource_arn=conflicting))),
            services_with_s3(),
        )


def test_normalization_uses_stable_edge_order_and_does_not_generate_reverse_edges():
    last = relationship(source=ref(resource_id="z-worker", resource_arn=None))
    first = relationship(source=ref(resource_id="a-worker", resource_arn=None))
    normalized = normalize_relationships((last, first), services_with_s3())
    assert [edge.source.resource_id for edge in normalized] == ["a-worker", "z-worker"]
    assert len(normalized) == 2
    assert all(edge.source.service == "lambda" for edge in normalized)


def test_collected_resource_arn_consistency_is_enforced():
    collected = Resource(
        service="lambda",
        resource_type="function",
        account_id=ACCOUNT,
        region=REGION,
        resource_id="worker",
        resource_arn=LAMBDA_ARN,
        data={},
    )
    services = {"lambda": CollectionResult([collected], [])}
    conflicting = ref(resource_arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:other")
    with pytest.raises(RelationshipError, match="ARN"):
        normalize_relationships((relationship(source=conflicting),), services)


def test_collected_resource_identity_is_enforced_when_arn_resolves():
    collected = Resource(
        service="lambda",
        resource_type="function",
        account_id=ACCOUNT,
        region=REGION,
        resource_id="worker",
        resource_arn=LAMBDA_ARN,
        data={},
    )
    services = {"lambda": CollectionResult([collected], [])}
    mismatched = ref(resource_id="other", resource_arn=LAMBDA_ARN)
    with pytest.raises(RelationshipError, match="identity"):
        normalize_relationships((relationship(source=mismatched),), services)


def test_conflicting_collected_arns_for_referenced_identity_are_rejected():
    first = Resource(
        service="lambda", resource_type="function", account_id=ACCOUNT, region=REGION,
        resource_id="worker", resource_arn=LAMBDA_ARN, data={},
    )
    second = Resource(
        service="lambda", resource_type="function", account_id=ACCOUNT, region=REGION,
        resource_id="worker",
        resource_arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:conflicting-locator",
        data={},
    )
    services = {"lambda": CollectionResult([first, second], [])}
    with pytest.raises(RelationshipError, match="ARN"):
        normalize_relationships((relationship(source=ref(resource_arn=None)),), services)


def test_projection_creates_supported_runs_as_relationships_and_skips_legacy_agentcore():
    bindings = [
        {"service": "lambda", "region": REGION, "resource_arn": LAMBDA_ARN, "role_arn": ROLE_ARN},
        {"service": "ec2", "region": REGION, "resource_arn": EC2_ARN, "role_arn": ROLE_ARN},
        {
            "service": "bedrock",
            "region": REGION,
            "resource_arn": f"arn:aws:bedrock:{REGION}:{ACCOUNT}:agent/ABCDEFGHIJ",
            "role_arn": ROLE_ARN,
        },
        {
            "service": "agentcore",
            "region": REGION,
            "resource_arn": f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/runtime_123",
            "role_arn": ROLE_ARN,
        },
    ]
    projected = project_relationships(iam_services(bindings))
    assert [(edge.source.service, edge.source.resource_type, edge.source.resource_id) for edge in projected] == [
        ("bedrock", "agent", "ABCDEFGHIJ"),
        ("ec2", "instance", "i-0123456789abcdef0"),
        ("lambda", "function", "worker"),
    ]
    assert all(edge.relationship_type is RelationshipType.RUNS_AS for edge in projected)
    assert all(edge.target == role_ref() for edge in projected)
    assert projected[0].evidence == (evidence(),)
    assert all(edge.evidence == (evidence(),) for edge in projected)


@pytest.mark.parametrize(
    "binding",
    [
        {"service": "lambda", "region": REGION, "resource_arn": "not-an-arn", "role_arn": ROLE_ARN},
        {"service": "lambda", "region": "us-east-1", "resource_arn": LAMBDA_ARN, "role_arn": ROLE_ARN},
        {
            "service": "lambda",
            "region": REGION,
            "resource_arn": f"arn:aws:lambda:{REGION}:{OTHER_ACCOUNT}:function:worker",
            "role_arn": ROLE_ARN,
        },
        {
            "service": "ec2",
            "region": REGION,
            "resource_arn": f"arn:aws:ec2:{REGION}:{ACCOUNT}:volume/vol-123",
            "role_arn": ROLE_ARN,
        },
        {
            "service": "ec2",
            "region": REGION,
            "resource_arn": f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-123456789",
            "role_arn": ROLE_ARN,
        },
    ],
)
def test_projection_omits_incomplete_or_unreliable_bindings(binding):
    assert project_relationships(iam_services([binding])) == ()


def test_projection_without_identity_bindings_is_empty():
    role = Resource(
        service="iam",
        resource_type="role",
        account_id=ACCOUNT,
        region=None,
        resource_id="worker-role",
        resource_arn=ROLE_ARN,
        data={},
    )
    assert project_relationships({"iam": CollectionResult([role], [])}) == ()


def test_v2_rejects_arbitrary_relationship_payload_keys():
    document = Snapshot(metadata(), services_with_s3(), (relationship(),), 2).to_dict()
    document["relationships"][0]["evidence"][0]["token"] = "secret-marker"
    with pytest.raises(SnapshotError) as error:
        snapshot_from_dict(document)
    assert "secret-marker" not in str(error.value)


def test_secret_validation_covers_the_complete_relationship_document():
    document = Snapshot(metadata(), services_with_s3(), (relationship(),), 2).to_dict()
    document["relationships"][0]["evidence"][0]["session_token"] = "secret-marker"
    with pytest.raises(SnapshotError, match="forbidden") as error:
        snapshot_from_dict(document)
    assert "secret-marker" not in str(error.value)


def test_future_non_null_operation_round_trips():
    edge = relationship(entries=(evidence(operation="FutureOperation"),))
    document = Snapshot(metadata(), services_with_s3(), (edge,), 2).to_dict()
    assert document["relationships"][0]["evidence"][0]["operation"] == "FutureOperation"
    assert snapshot_from_dict(document).relationships[0].evidence[0].operation == "FutureOperation"


def test_v2_accepts_dangling_unregistered_endpoint_refs():
    edge = Relationship(
        source=ref("future-service", "future_type", ACCOUNT, REGION, "source", None),
        relationship_type=RelationshipType.INVOKES,
        target=ref("another-service", "target_type", OTHER_ACCOUNT, "us-west-2", "target", None),
        evidence=(evidence("future-service", "observed_target", "FutureOperation"),),
    )
    restored = snapshot_from_dict(Snapshot(metadata(), services_with_s3(), (edge,), 2).to_dict())
    assert restored.relationships == (edge,)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda item: item.update(extra="value"),
        lambda item: item["source"].update(extra="value"),
        lambda item: item["evidence"][0].pop("operation"),
        lambda item: item.update(type="ACTION_GROUP"),
        lambda item: item.update(evidence=[]),
    ],
)
def test_v2_rejects_non_contract_relationship_shapes(mutate):
    document = Snapshot(metadata(), services_with_s3(), (relationship(),), 2).to_dict()
    mutate(document["relationships"][0])
    with pytest.raises(SnapshotError):
        snapshot_from_dict(document)


def test_relationships_do_not_change_findings_or_coverage():
    legacy = Snapshot(metadata(), services_with_s3())
    current = Snapshot(metadata(), services_with_s3(), (relationship(),), 2)
    before = evaluate_snapshot(legacy).to_dict()
    after = evaluate_snapshot(current).to_dict()
    assert after == before


def test_mixed_v1_v2_diff_and_history_remain_finding_based():
    before = Snapshot(metadata(), services_with_s3())
    later_metadata = replace(metadata(), scan_id="relationships-later",
                             started_at=metadata().started_at + timedelta(minutes=1))
    after = Snapshot(later_metadata, services_with_s3(), (relationship(),), 2)
    comparison = compare_snapshots(before, after)
    history = finding_history([before, after])
    assert comparison["summary"] == {"NEW": 0, "RESOLVED": 0, "UNCHANGED": 1, "UNKNOWN": 0}
    assert len(history["findings"]) == 1
    assert history["findings"][0]["observed_scan_count"] == 2


def test_live_capture_explicitly_writes_v2_and_projects_existing_bindings(monkeypatch):
    services = iam_services([{
        "service": "lambda",
        "region": REGION,
        "resource_arn": LAMBDA_ARN,
        "role_arn": ROLE_ARN,
    }])
    collector = Mock(return_value=services["iam"])
    monkeypatch.setattr("awsherlock.snapshot.service_components", lambda service: (collector, ()))
    context = Mock(account_id=ACCOUNT, region=REGION, caller_arn="arn:aws:iam::123456789012:user/test",
                   measurements=None)
    captured = capture_snapshot(context, ["iam"])
    assert captured.schema_version == 2
    assert captured.relationships == project_relationships(services)
    collector.assert_called_once_with(context)
