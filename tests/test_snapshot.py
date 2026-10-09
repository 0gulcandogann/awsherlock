from datetime import datetime, timezone
from unittest.mock import Mock
import json
import pytest
from typer.testing import CliRunner
from awsherlock.cli import app
from awsherlock.collectors.common import CollectionResult, CollectionIssue
from awsherlock.models import Relationship, RelationshipEvidence, RelationshipType, Resource, ResourceRef, ScanMetadata
from awsherlock.snapshot import (
    CURRENT_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    Snapshot,
    SnapshotError,
    read_snapshot,
    snapshot_from_dict,
    write_snapshot,
)


@pytest.fixture
def snapshot():
    metadata = ScanMetadata(scan_id="test", started_at=datetime(2026, 9, 15, tzinfo=timezone.utc), account_id="123456789012", region=None, version="test")
    resource = Resource(service="s3", resource_type="bucket", account_id=metadata.account_id, region="us-east-1", resource_id="test-bucket", resource_arn=None, data={"public_access_block": None, "account_public_access_block": None})
    return Snapshot(metadata, {"s3": CollectionResult([resource], [CollectionIssue("test-bucket", "GetBucketLogging", "AccessDenied")])})


def test_round_trip(snapshot, tmp_path):
    path = tmp_path / "snapshot.json"
    write_snapshot(snapshot, path)
    restored = read_snapshot(path)
    assert restored.to_dict() == snapshot.to_dict()
    assert restored.services["s3"].issues[0].message == "AccessDenied"
    with pytest.raises(FileExistsError):
        write_snapshot(snapshot, path)


def test_snapshot_v1_serialization_matches_pre_registry_contract(snapshot):
    assert snapshot.to_dict() == {
        "schema_version": 1,
        "metadata": {
            "scan_id": "test",
            "started_at": "2026-09-15T00:00:00+00:00",
            "account_id": "123456789012",
            "region": None,
            "version": "test",
        },
        "services": {
            "s3": {
                "resources": [{
                    "service": "s3",
                    "resource_type": "bucket",
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "resource_id": "test-bucket",
                    "resource_arn": None,
                    "data": {
                        "public_access_block": None,
                        "account_public_access_block": None,
                    },
                }],
                "issues": [{
                    "resource_id": "test-bucket",
                    "operation": "GetBucketLogging",
                    "message": "AccessDenied",
                }],
            },
        },
    }


def test_legacy_constructor_remains_v1_without_relationship_capability(snapshot):
    assert snapshot.schema_version == 1
    assert snapshot.relationships == ()
    assert not snapshot.supports_relationships
    assert CURRENT_SCHEMA_VERSION == 2
    assert SUPPORTED_SCHEMA_VERSIONS == frozenset({1, 2})


def test_v1_cannot_contain_relationships(snapshot):
    reference = ResourceRef(service="lambda", resource_type="function", account_id="123456789012",
                            region="us-east-1", resource_id="worker", resource_arn=None)
    edge = Relationship(source=reference, relationship_type=RelationshipType.USES, target=reference,
                        evidence=(RelationshipEvidence(service="iam", fact="identity_bindings"),))
    with pytest.raises(SnapshotError, match="version 1"):
        Snapshot(snapshot.metadata, snapshot.services, (edge,)).to_dict()


def test_v2_empty_relationships_round_trip(snapshot):
    current = Snapshot(snapshot.metadata, snapshot.services, (), 2)
    document = current.to_dict()
    assert list(document) == ["schema_version", "metadata", "services", "relationships"]
    assert document["schema_version"] == 2
    assert document["relationships"] == []
    restored = snapshot_from_dict(document)
    assert restored.schema_version == 2
    assert restored.supports_relationships
    assert restored.relationships == ()
    assert restored.to_dict() == document


def test_v2_relationship_round_trip_uses_stable_json_keys(snapshot):
    source = ResourceRef(service="lambda", resource_type="function", account_id="123456789012",
                         region="us-east-1", resource_id="worker",
                         resource_arn="arn:aws:lambda:us-east-1:123456789012:function:worker")
    target = ResourceRef(service="iam", resource_type="role", account_id="123456789012",
                         region=None, resource_id="worker-role",
                         resource_arn="arn:aws:iam::123456789012:role/worker-role")
    edge = Relationship(source=source, relationship_type=RelationshipType.RUNS_AS, target=target,
                        evidence=(RelationshipEvidence(service="iam", fact="identity_bindings"),))
    document = Snapshot(snapshot.metadata, snapshot.services, (edge,), 2).to_dict()
    assert document["relationships"] == [{
        "source": {
            "service": "lambda",
            "resource_type": "function",
            "account_id": "123456789012",
            "region": "us-east-1",
            "resource_id": "worker",
            "resource_arn": "arn:aws:lambda:us-east-1:123456789012:function:worker",
        },
        "type": "RUNS_AS",
        "target": {
            "service": "iam",
            "resource_type": "role",
            "account_id": "123456789012",
            "region": None,
            "resource_id": "worker-role",
            "resource_arn": "arn:aws:iam::123456789012:role/worker-role",
        },
        "evidence": [{"service": "iam", "fact": "identity_bindings", "operation": None}],
    }]
    assert snapshot_from_dict(document).to_dict() == document


@pytest.mark.parametrize("field", ["Credentials", "AccessKeyId", "SecretAccessKey", "SessionToken", "SecretString", "PrivateKey", "Environment"])
def test_forbidden_fields(snapshot, field):
    snapshot.services["s3"].resources[0].data["public_access_block"] = {field: "secret-marker"}
    with pytest.raises(SnapshotError) as error:
        snapshot.to_dict()
    assert "secret-marker" not in str(error.value)


def test_invalid_schema_and_unknown_fact(snapshot):
    data = snapshot.to_dict()
    data["schema_version"] = 3
    with pytest.raises(SnapshotError, match="schema"):
        snapshot_from_dict(data)
    data["schema_version"] = 1
    data["services"]["s3"]["resources"][0]["data"]["arbitrary"] = "value"
    with pytest.raises(SnapshotError):
        snapshot_from_dict(data)


def test_duplicate_json_keys(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":1,"schema_version":2}')
    with pytest.raises(SnapshotError):
        read_snapshot(path)


def test_snapshot_cli(snapshot, monkeypatch, tmp_path):
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock())
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", Mock(return_value=snapshot))
    path = tmp_path / "new.json"
    result = CliRunner().invoke(app, ["snapshot", "--services", "s3", "--output", str(path)])
    assert result.exit_code == 1  # Coverage is partial, but snapshot remains useful.
    assert path.exists()
    assert "incomplete" in result.output
    assert "session" not in path.read_text()
