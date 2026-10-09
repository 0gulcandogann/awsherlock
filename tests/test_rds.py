"""RDS public manual snapshot checks with mocked AWS reads."""

from datetime import datetime, timezone
from dataclasses import replace
from types import SimpleNamespace

from botocore.exceptions import ClientError
import pytest

from awsherlock.collectors.common import CollectionResult
from awsherlock.collectors.rds import collect_rds
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.models import Resource, ScanMetadata
from awsherlock.scanner import parse_services
from awsherlock.snapshot import Snapshot, capture_snapshot, snapshot_from_dict
from awsherlock.reporting import render_json, render_html, render_console
from awsherlock.sarif import render_sarif


ACCOUNT = "123456789012"
REGION = "eu-west-1"


def record(kind, name):
    prefix = "DB" if kind == "db" else "DBCluster"
    arn_kind = "snapshot" if kind == "db" else "cluster-snapshot"
    return {f"{prefix}SnapshotIdentifier": name,
            f"{prefix}SnapshotArn": f"arn:aws:rds:{REGION}:{ACCOUNT}:{arn_kind}:{name}"}


class Paginator:
    def __init__(self, pages, *, snapshot=True):
        self.pages = pages
        self.snapshot = snapshot

    def paginate(self, **kwargs):
        assert kwargs == ({"SnapshotType": "manual"} if self.snapshot else {})
        yield from self.pages


class RDSClient:
    def __init__(self, *, denied=None, malformed=False):
        self.denied = denied
        self.malformed = malformed

    def get_paginator(self, operation):
        if operation == "describe_db_instances":
            return Paginator([{"DBInstances": []}], snapshot=False)
        if operation == "describe_db_snapshots":
            return Paginator([{"DBSnapshots": [record("db", "private")]},
                              {"DBSnapshots": [record("db", "public")]}])
        assert operation == "describe_db_cluster_snapshots"
        return Paginator([{"DBClusterSnapshots": [record("cluster", "aurora")]}])

    def _attributes(self, name, key):
        if self.denied == name:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, key)
        if self.malformed and name == "aurora":
            return {key: {"DBSnapshotAttributes": []}}
        attribute = "DBSnapshotAttributes" if key == "DBSnapshotAttributesResult" else "DBClusterSnapshotAttributes"
        return {key: {attribute: [{"AttributeName": "restore",
                                   "AttributeValues": ["all"] if name != "private" else []}]}}

    def describe_db_snapshot_attributes(self, *, DBSnapshotIdentifier):
        return self._attributes(DBSnapshotIdentifier, "DBSnapshotAttributesResult")

    def describe_db_cluster_snapshot_attributes(self, *, DBClusterSnapshotIdentifier):
        return self._attributes(DBClusterSnapshotIdentifier, "DBClusterSnapshotAttributesResult")


def collect(client):
    context = SimpleNamespace(account_id=ACCOUNT, partition="aws", region=REGION,
                              client=lambda service, **kwargs: client)
    return collect_rds(context)


def report_for(result):
    metadata = ScanMetadata(scan_id="test", started_at=datetime.now(timezone.utc),
                            account_id=ACCOUNT, region=REGION, version="test")
    snapshot = Snapshot(metadata, {"rds": result})
    return evaluate_snapshot(snapshot), snapshot


def test_public_and_private_snapshot_types_paginate_and_roundtrip():
    result = collect(RDSClient())
    assert not result.issues
    assert [r.resource_id for r in result.resources] == [
        "db-snapshot:private", "db-snapshot:public", "db-cluster-snapshot:aurora"]
    report, snapshot = report_for(result)
    assert {f.resource_id for f in report.findings} == {"db-snapshot:public", "db-cluster-snapshot:aurora"}
    assert {f.id for f in report.findings} == {"AWSH-RDS-001"}
    assert report.coverage[0]["status"] == "COMPLETE"
    assert result.completed_operations == ["DescribeDBInstances"]
    assert len(snapshot_from_dict(snapshot.to_dict()).services["rds"].resources) == 3
    assert "rds" not in parse_services(None)
    assert parse_services("rds") == ["rds"]


def test_denied_detail_is_not_pass_and_other_snapshots_still_evaluate():
    result = collect(RDSClient(denied="public"))
    report, _ = report_for(result)
    assert any(issue.operation == "DescribeDBSnapshotAttributes" and issue.resource_id == "db-snapshot:public"
               and issue.message == "AccessDenied"
               for issue in result.issues)
    assert {f.resource_id for f in report.findings} == {"db-cluster-snapshot:aurora"}
    assert report.coverage[0]["status"] == "PARTIAL"
    assert any(issue["operation"] == "RequiredFact" and issue["resource_id"] == "db-snapshot:public"
               for issue in report.coverage[0]["issues"])
    assert any(issue["operation"] == "RequiredFact" and
               "a related collection issue is recorded separately" in issue["message"]
               for issue in report.coverage[0]["issues"])


def test_invalid_cluster_attributes_leave_missing_fact():
    result = collect(RDSClient(malformed=True))
    report, _ = report_for(result)
    assert "restore_public" not in result.resources[-1].data
    assert {f.resource_id for f in report.findings} == {"db-snapshot:public"}
    assert report.coverage[0]["status"] == "PARTIAL"


def test_snapshot_rejects_non_boolean_restore_fact():
    result = CollectionResult([Resource(service="rds", resource_type="db-snapshot", account_id=ACCOUNT,
                                        region=REGION, resource_id="db-snapshot:x",
                                        resource_arn=f"arn:aws:rds:{REGION}:{ACCOUNT}:snapshot:x",
                                        data={"restore_public": "false"})], [])
    _, snapshot = report_for(CollectionResult())
    snapshot.services["rds"] = result
    try:
        snapshot_from_dict(snapshot.to_dict())
    except ValueError:
        pass
    else:
        raise AssertionError("invalid RDS fact accepted")


def test_same_snapshot_name_has_distinct_types_and_report_outputs(capsys):
    result = collect(RDSClient())
    result.resources[-1] = replace(result.resources[-1], resource_id="db-cluster-snapshot:public",
                                   resource_arn=f"arn:aws:rds:{REGION}:{ACCOUNT}:cluster-snapshot:public")
    report, snapshot = report_for(result)
    replayed = evaluate_snapshot(snapshot_from_dict(snapshot.to_dict()))
    assert {f.resource_id for f in replayed.findings} == {
        "db-snapshot:public", "db-cluster-snapshot:public"}
    for rendered in (render_json(report), render_html(report), render_sarif(report)):
        assert "AWSH-RDS-001" in rendered
        assert "secret-access-key-marker" not in rendered
    render_console(report)
    assert "AWSH-RDS-001" in capsys.readouterr().out


def test_empty_lists_are_complete_and_no_findings():
    class EmptyClient(RDSClient):
        def get_paginator(self, operation):
            if operation == "describe_db_instances":
                return Paginator([{"DBInstances": []}], snapshot=False)
            key = "DBSnapshots" if operation == "describe_db_snapshots" else "DBClusterSnapshots"
            return Paginator([{key: []}])

    report, _ = report_for(collect(EmptyClient()))
    assert not report.findings
    assert report.coverage[0]["status"] == "COMPLETE"


def test_live_capture_preserves_empty_instance_listing_completion():
    class EmptyClient(RDSClient):
        def get_paginator(self, operation):
            if operation == "describe_db_instances":
                return Paginator([{"DBInstances": []}], snapshot=False)
            key = "DBSnapshots" if operation == "describe_db_snapshots" else "DBClusterSnapshots"
            return Paginator([{key: []}])

    context = SimpleNamespace(account_id=ACCOUNT, partition="aws", region=REGION,
                              measurements=None, client=lambda service, **kwargs: EmptyClient())
    snapshot = capture_snapshot(context, ["rds"])
    assert snapshot.to_dict()["services"]["rds"]["completed_operations"] == ["DescribeDBInstances"]
    replayed = evaluate_snapshot(snapshot_from_dict(snapshot.to_dict()))
    assert replayed.coverage[0]["status"] == "COMPLETE"
    assert not replayed.findings


def instance(name, encrypted, *, engine="postgres", cluster=None, public=False):
    value = {"DBInstanceIdentifier": name,
             "DBInstanceArn": f"arn:aws:rds:{REGION}:{ACCOUNT}:db:{name}",
             "Engine": engine, "StorageEncrypted": encrypted,
             "PubliclyAccessible": public}
    if cluster is not None:
        value["DBClusterIdentifier"] = cluster
    return value


class InstanceClient(RDSClient):
    def __init__(self, pages, *, denied=False):
        super().__init__()
        self.pages = pages
        self.instance_denied = denied

    def get_paginator(self, operation):
        if operation == "describe_db_instances":
            if self.instance_denied:
                raise ClientError({"Error": {"Code": "AccessDenied"}}, "DescribeDBInstances")
            return Paginator(self.pages, snapshot=False)
        return super().get_paginator(operation)


def test_instance_encryption_pagination_and_replay():
    pages = [{"DBInstances": [instance("encrypted", True),
                              instance("cluster-member", False, cluster="multi-az"),
                              instance("aurora-member", False, engine="aurora-postgresql")]},
             {"DBInstances": [instance("unencrypted", False, engine="mysql", public=True)]}]
    result = collect(InstanceClient(pages))
    report, snapshot = report_for(result)
    assert [r.resource_id for r in result.resources if r.resource_type == "db-instance"] == [
        "db-instance:encrypted", "db-instance:unencrypted"]
    findings = [f for f in report.findings if f.id == "AWSH-RDS-002"]
    assert [(f.resource_id, f.evidence) for f in findings] == [
        ("db-instance:unencrypted", {"storage_encrypted": False})]
    public_findings = [f for f in report.findings if f.id == "AWSH-RDS-003"]
    assert [(f.resource_id, f.evidence) for f in public_findings] == [
        ("db-instance:unencrypted", {"publicly_accessible": True})]
    assert report.coverage[0]["status"] == "COMPLETE"
    for rendered in (render_json(report), render_html(report), render_sarif(report)):
        assert "AWSH-RDS-002" in rendered
        assert "AWSH-RDS-003" in rendered
    assert [f.to_dict() for f in evaluate_snapshot(snapshot_from_dict(snapshot.to_dict())).findings] == [
        f.to_dict() for f in report.findings]
    assert snapshot.to_dict()["services"]["rds"]["completed_operations"] == ["DescribeDBInstances"]


def test_instance_listing_denied_keeps_snapshot_finding_and_incomplete_coverage():
    result = collect(InstanceClient([], denied=True))
    report, _ = report_for(result)
    assert not result.completed_operations
    assert {f.id for f in report.findings} == {"AWSH-RDS-001"}
    assert report.coverage[0]["status"] == "PARTIAL"
    assert any(issue["operation"] == "DescribeDBInstances" and issue["message"] == "AccessDenied"
               for issue in report.coverage[0]["issues"])


def test_instance_missing_or_malformed_encryption_is_incomplete_not_pass():
    result = collect(InstanceClient([{"DBInstances": [instance("unknown", None),
                                                     instance("unrecognized", False, engine="future-engine")]}]))
    report, _ = report_for(result)
    assert not any(f.id == "AWSH-RDS-002" for f in report.findings)
    assert report.coverage[0]["status"] == "PARTIAL"
    assert any(issue["operation"] == "RequiredFact" and issue["resource_id"] == "db-instance:unknown"
               for issue in report.coverage[0]["issues"])
    assert any(issue["operation"] == "DescribeDBInstances" and issue["resource_id"] == "db-instance:unrecognized"
               for issue in report.coverage[0]["issues"])


def test_missing_public_access_flag_and_old_snapshot_are_incomplete():
    missing = instance("missing", True)
    missing.pop("PubliclyAccessible")
    result = collect(InstanceClient([{"DBInstances": [missing]}]))
    report, snapshot = report_for(result)
    assert not any(f.id == "AWSH-RDS-003" for f in report.findings)
    assert report.coverage[0]["status"] == "PARTIAL"
    assert any(issue["operation"] == "RequiredFact" and "AWSH-RDS-003" in issue["message"]
               for issue in report.coverage[0]["issues"])
    _, complete_snapshot = report_for(collect(InstanceClient([{"DBInstances": [instance("old", True)]}])))
    old = complete_snapshot.to_dict()
    old["services"]["rds"]["resources"][-1]["data"].pop("publicly_accessible")
    replay = evaluate_snapshot(snapshot_from_dict(old))
    assert replay.coverage[0]["status"] == "PARTIAL"


def test_malformed_public_access_flag_is_incomplete_not_a_finding():
    result = collect(InstanceClient([{"DBInstances": [instance("wrong", True, public="true")]}]))
    report, _ = report_for(result)
    assert not any(f.id == "AWSH-RDS-003" for f in report.findings)
    assert report.coverage[0]["status"] == "PARTIAL"
    assert any(issue["operation"] == "DescribeDBInstances" and issue["resource_id"] == "db-instance:wrong"
               for issue in report.coverage[0]["issues"])


def test_malformed_instance_page_does_not_mark_listing_complete():
    result = collect(InstanceClient([{"Unexpected": []}]))
    report, _ = report_for(result)
    assert not result.completed_operations
    assert report.coverage[0]["status"] == "PARTIAL"
    assert any(issue["operation"] == "DescribeDBInstances" and issue["message"] == "Invalid AWS response"
               for issue in report.coverage[0]["issues"])


def test_old_rds_snapshot_is_readable_but_does_not_claim_instance_coverage():
    _, snapshot = report_for(collect(RDSClient()))
    old = snapshot.to_dict()
    old["services"]["rds"].pop("completed_operations")
    replay = snapshot_from_dict(old)
    report = evaluate_snapshot(replay)
    assert report.coverage[0]["status"] == "PARTIAL"
    assert any(issue["operation"] == "RequiredCollection" for issue in report.coverage[0]["issues"])
    assert any(issue["operation"] == "RequiredCollection" for issue in
               evaluate_snapshot(replay, selected_checks=["AWSH-RDS-003"]).coverage[0]["issues"])
    assert not any(issue["operation"] == "RequiredCollection" for issue in
                   evaluate_snapshot(replay, selected_checks=["AWSH-RDS-001"]).coverage[0]["issues"])


def test_instance_fact_and_collection_marker_reject_invalid_snapshot_values():
    _, snapshot = report_for(collect(InstanceClient([{"DBInstances": [instance("x", False)]}])))
    bad_fact = snapshot.to_dict()
    bad_fact["services"]["rds"]["resources"][-1]["data"]["storage_encrypted"] = "false"
    with pytest.raises(ValueError):
        snapshot_from_dict(bad_fact)
    bad_marker = snapshot.to_dict()
    bad_marker["services"]["rds"]["completed_operations"] = ["DescribeDBInstances", "GetSecretValue"]
    with pytest.raises(ValueError):
        snapshot_from_dict(bad_marker)


def test_mismatched_owner_is_an_issue_not_a_finding():
    class WrongOwner(RDSClient):
        def get_paginator(self, operation):
            if operation == "describe_db_instances":
                return Paginator([{"DBInstances": []}], snapshot=False)
            if operation == "describe_db_snapshots":
                item = record("db", "foreign")
                item["DBSnapshotArn"] = item["DBSnapshotArn"].replace(ACCOUNT, "999999999999")
                return Paginator([{"DBSnapshots": [item]}])
            return Paginator([{"DBClusterSnapshots": []}])

    result = collect(WrongOwner())
    report, _ = report_for(result)
    assert not report.findings and not result.resources
    assert report.coverage[0]["status"] != "COMPLETE"
    assert result.issues[0].message == "Invalid AWS response"


def test_denied_db_listing_does_not_discard_cluster_finding():
    class DeniedDB(RDSClient):
        def get_paginator(self, operation):
            if operation == "describe_db_snapshots":
                raise ClientError({"Error": {"Code": "AccessDenied"}}, operation)
            return super().get_paginator(operation)

    result = collect(DeniedDB())
    report, _ = report_for(result)
    assert {f.resource_id for f in report.findings} == {"db-cluster-snapshot:aurora"}
    assert report.coverage[0]["status"] == "PARTIAL"
    assert any(issue.operation == "DescribeDBSnapshots" and issue.message == "AccessDenied"
               for issue in result.issues)


def test_cluster_snapshot_pagination_and_private_restore():
    class ClusterPages(RDSClient):
        def get_paginator(self, operation):
            if operation == "describe_db_cluster_snapshots":
                return Paginator([{"DBClusterSnapshots": [record("cluster", "aurora")]},
                                  {"DBClusterSnapshots": [record("cluster", "private")]}])
            return super().get_paginator(operation)

    result = collect(ClusterPages())
    report, _ = report_for(result)
    assert [r.resource_id for r in result.resources if r.resource_type == "db-cluster-snapshot"] == [
        "db-cluster-snapshot:aurora", "db-cluster-snapshot:private"]
    assert {f.resource_id for f in report.findings} == {"db-snapshot:public", "db-cluster-snapshot:aurora"}
    assert report.coverage[0]["status"] == "COMPLETE"
