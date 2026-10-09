"""Real SDK event measurements with offline Stubber responses only."""

from dataclasses import replace
import json
from unittest.mock import Mock

import boto3
import pytest
from botocore.exceptions import ClientError, ReadTimeoutError
from botocore.stub import Stubber

from awsherlock.aws.context import ScanContext
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.measurement import ScanMeasurements
from awsherlock.organization import scan_organization
from awsherlock.regional import scan_regions
from awsherlock.snapshot import capture_snapshot

ACCOUNT = "123456789012"
IDENTITY = f"arn:aws:iam::{ACCOUNT}:role/Reader"


def sdk_client(service, region="eu-west-1"):
    return boto3.client(service, region_name=region, aws_access_key_id="synthetic",
                        aws_secret_access_key="synthetic")


def context(client, measurements=None):
    return ScanContext(ACCOUNT, IDENTITY, "aws", None, "eu-west-1",
                       Mock(client=Mock(return_value=client)), measurements=measurements)


def operation_counts(measurements):
    return {row["operation"]: row["count"] for row in measurements.to_dict()["calls"]}


def test_pagination_counts_denial_and_handler_cleanup():
    client = sdk_client("kms")
    with Stubber(client) as stub:
        stub.add_response("list_keys", {"Keys": [], "Truncated": True, "NextMarker": "page-2"}, {})
        stub.add_client_error("list_keys", "AccessDeniedException", "payload-secret", expected_params={"Marker": "page-2"})
        stub.add_response("list_keys", {"Keys": []}, {})
        with ScanMeasurements() as measurements:
            target = context(client, measurements)
            report = evaluate_snapshot(capture_snapshot(target, ["kms"]))
            assert report.incomplete and report.coverage[0]["status"] == "ACCESS_DENIED"
            assert operation_counts(measurements) == {"ListKeys": 2}
            assert len(measurements.to_dict()["collections"]) == 1
            target.client("kms")  # Re-registering the same client must not double count.
        client.list_keys()
        assert operation_counts(measurements) == {"ListKeys": 2}
        assert "payload-secret" not in json.dumps(measurements.to_dict())
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("failure", [
    ReadTimeoutError(endpoint_url="https://secret.invalid"),
    ClientError({"Error": {"Code": "ExpiredToken", "Message": "secret-marker"}}, "ListKeys"),
])
def test_failed_call_is_counted_without_payload(failure):
    client = sdk_client("kms")
    def fail(**kwargs):
        raise failure
    client.meta.events.register("before-call.kms.ListKeys", fail)
    with ScanMeasurements() as measurements:
        report = evaluate_snapshot(capture_snapshot(context(client, measurements), ["kms"]))
        assert report.incomplete
        assert operation_counts(measurements) == {"ListKeys": 1}
        assert measurements.to_dict()["collections"][0]["seconds"][0] >= 0
        assert "secret" not in json.dumps(measurements.to_dict())


def test_identity_region_isolation_and_fresh_scan_reset():
    with ScanMeasurements() as measurements:
        for index, (account, identity, region) in enumerate([
            (ACCOUNT, IDENTITY, "eu-west-1"),
            (ACCOUNT, IDENTITY + "Other", "eu-west-1"),
            (ACCOUNT, IDENTITY, "eu-central-1"),
            ("999999999999", "another-identity", "eu-west-1"),
        ]):
            client = sdk_client("kms", region)
            with Stubber(client) as stub:
                stub.add_response("list_keys", {"Keys": []}, {})
                measurements.instrument(client, account, identity)
                client.list_keys()
        rows = measurements.to_dict()["calls"]
        assert len(rows) == 4 and all(row["count"] == 1 for row in rows)
        account_rows = [row for row in rows if row["account_id"] == ACCOUNT]
        central_scope = next(row["identity_scope"] for row in account_rows
                             if row["region"] == "eu-central-1")
        west_scopes = {row["identity_scope"] for row in account_rows
                       if row["region"] == "eu-west-1"}
        assert central_scope in west_scopes and len(west_scopes) == 2
        assert IDENTITY not in json.dumps(measurements.to_dict())
    with ScanMeasurements() as fresh:
        assert fresh.to_dict()["calls"] == []
    with pytest.raises(RuntimeError):
        fresh.instrument(client, ACCOUNT, IDENTITY)


def test_region_orchestration_counts_and_report_equivalence():
    clients = [sdk_client("kms", region) for region in ["eu-west-1", "eu-central-1"]]
    with Stubber(clients[0]) as first, Stubber(clients[1]) as second:
        first.add_response("list_keys", {"Keys": []}, {})
        second.add_client_error("list_keys", "AccessDeniedException", "hidden", expected_params={})
        with ScanMeasurements() as measurements:
            target = context(clients[0], measurements)
            target.session.client.side_effect = clients
            report = scan_regions(target, ["kms"], ["eu-west-1", "eu-central-1"])
            assert [entry["status"] for entry in report.coverage] == ["COMPLETE", "ACCESS_DENIED"]
            assert len(measurements.to_dict()["calls"]) == 2
            assert len(measurements.to_dict()["collections"]) == 2
            assert "calls" not in report.to_dict()["metadata"]


def test_collection_timer_retained_if_collector_raises(monkeypatch):
    ticks = iter([5.0, 5.25])
    monkeypatch.setattr("awsherlock.measurement.perf_counter", lambda: next(ticks))
    monkeypatch.setattr("awsherlock.snapshot.service_components",
                        lambda service: (Mock(side_effect=ValueError("bad collector")), []))
    with ScanMeasurements() as measurements:
        with pytest.raises(ValueError):
            capture_snapshot(context(None, measurements), ["kms"])
        assert measurements.to_dict()["collections"][0]["seconds"] == [0.25]


def test_organization_discovery_and_member_measurements(monkeypatch):
    org = sdk_client("organizations")
    kms = sdk_client("kms")
    member = replace(context(kms), account_id="999999999999", caller_arn="member-identity")
    factory = Mock(return_value=member)
    monkeypatch.setattr("awsherlock.organization.create_scan_context", factory)
    with Stubber(org) as discovery, Stubber(kms) as inventory:
        discovery.add_response("list_accounts", {"Accounts": [{"Id": member.account_id,
                                "Name": "Synthetic", "State": "ACTIVE"}]}, {})
        inventory.add_response("list_keys", {"Keys": []}, {})
        with ScanMeasurements() as measurements:
            report = scan_organization(context(org, measurements), ["kms"])
            assert not report.incomplete
            rows = measurements.to_dict()["calls"]
            assert {(r["account_id"], r["operation"]) for r in rows} == {
                (ACCOUNT, "ListAccounts"), (member.account_id, "ListKeys")}
            assert factory.call_args.kwargs["source_session"] is not None


def test_opt_in_does_not_change_snapshot_or_report():
    snapshots = []
    for measured in [False, True]:
        client = sdk_client("kms")
        with Stubber(client) as stub, ScanMeasurements() as measurements:
            stub.add_response("list_keys", {"Keys": []}, {})
            snapshots.append(capture_snapshot(context(client, measurements if measured else None), ["kms"]))
    snapshots[1].metadata = snapshots[0].metadata
    assert snapshots[0].to_dict() == snapshots[1].to_dict()
    assert evaluate_snapshot(snapshots[0]).to_dict() == evaluate_snapshot(snapshots[1]).to_dict()
