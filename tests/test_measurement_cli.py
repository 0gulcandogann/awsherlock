"""Opt-in CLI measurement export uses synthetic SDK responses only."""

import json
from dataclasses import replace
from unittest.mock import Mock

from botocore.stub import Stubber
from typer.testing import CliRunner

from awsherlock.cli import app
from test_measurement import context, sdk_client
from test_cli_options import no_aws


def test_live_measurement_file_counts_sdk_calls_and_keeps_report_schema(tmp_path, monkeypatch):
    client = sdk_client("kms")
    monkeypatch.setattr("awsherlock.cli.create_scan_context", lambda **kwargs: context(client))
    destination = tmp_path / "measurements.json"
    with Stubber(client) as stub:
        stub.add_response("list_keys", {"Keys": []}, {})
        result = CliRunner().invoke(app, ["scan", "--services", "kms", "--output", "json",
                                          "--no-progress", "--measurements-file", str(destination)])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    data = json.loads(destination.read_text(encoding="utf-8"))
    assert "measurements" not in report and "calls" not in report["metadata"]
    assert data["schema_version"] == 1
    assert data["calls"] == [{"account_id": "123456789012", "identity_scope": 1,
                              "region": "eu-west-1", "service": "kms", "operation": "ListKeys", "count": 1}]
    assert len(data["collections"]) == 1 and data["collections"][0]["seconds"][0] >= 0
    assert not data["authentication_calls_included"]
    assert "arn:aws:" not in json.dumps(data)
    assert "Measurements saved:" in result.stderr


def test_denied_collection_still_writes_measurements_without_error_payload(tmp_path, monkeypatch):
    client = sdk_client("kms")
    monkeypatch.setattr("awsherlock.cli.create_scan_context", lambda **kwargs: context(client))
    destination = tmp_path / "measurements.json"
    with Stubber(client) as stub:
        stub.add_client_error("list_keys", "AccessDeniedException", "private-marker", expected_params={})
        result = CliRunner().invoke(app, ["scan", "--services", "kms", "--output", "json",
                                          "--no-progress", "--measurements-file", str(destination)])
    assert result.exit_code == 1 and json.loads(result.stdout)["summary"]["incomplete"]
    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data["calls"][0]["operation"] == "ListKeys" and data["calls"][0]["count"] == 1
    assert "private-marker" not in json.dumps(data)


def test_multi_region_measurement_file_keeps_regions_separate(tmp_path, monkeypatch):
    west, central = sdk_client("kms", "eu-west-1"), sdk_client("kms", "eu-central-1")
    source = context(west)
    source.session.client.side_effect = [west, central]
    monkeypatch.setattr("awsherlock.cli.create_scan_context", lambda **kwargs: source)
    destination = tmp_path / "measurements.json"
    with Stubber(west) as first, Stubber(central) as second:
        first.add_response("list_keys", {"Keys": []}, {})
        second.add_response("list_keys", {"Keys": []}, {})
        result = CliRunner().invoke(app, ["scan", "--services", "kms", "--regions",
                                          "eu-west-1,eu-central-1", "--no-progress",
                                          "--measurements-file", str(destination)])
    assert result.exit_code == 0, result.output
    rows = json.loads(destination.read_text(encoding="utf-8"))["calls"]
    assert {(row["region"], row["operation"], row["count"]) for row in rows} == {
        ("eu-west-1", "ListKeys", 1), ("eu-central-1", "ListKeys", 1)}


def test_organization_measurement_file_includes_discovery_and_member(tmp_path, monkeypatch):
    org, kms = sdk_client("organizations"), sdk_client("kms")
    source = context(org)
    member = replace(context(kms), account_id="999999999999", caller_arn="member-identity")
    monkeypatch.setattr("awsherlock.cli.create_scan_context", lambda **kwargs: source)
    monkeypatch.setattr("awsherlock.organization.create_scan_context", Mock(return_value=member))
    destination = tmp_path / "measurements.json"
    with Stubber(org) as discovery, Stubber(kms) as inventory:
        discovery.add_response("list_accounts", {"Accounts": [{"Id": member.account_id,
                                "Name": "Synthetic", "State": "ACTIVE"}]}, {})
        inventory.add_response("list_keys", {"Keys": []}, {})
        result = CliRunner().invoke(app, ["scan", "organization", "--services", "kms",
                                          "--no-progress", "--measurements-file", str(destination)])
    assert result.exit_code == 0, result.output
    rows = json.loads(destination.read_text(encoding="utf-8"))["calls"]
    assert {(row["account_id"], row["operation"]) for row in rows} == {
        ("123456789012", "ListAccounts"), ("999999999999", "ListKeys")}


def test_measurement_file_rejects_offline_preview_and_collisions_before_aws(tmp_path, no_aws):
    destination = tmp_path / "new.json"
    destination.write_text("existing", encoding="utf-8")
    cases = [
        ["scan", "--measurements-file", str(destination)],
        ["scan", "--preview", "--measurements-file", str(tmp_path / "preview.json")],
        ["scan", str(tmp_path / "facts.json"), "--measurements-file", str(tmp_path / "offline.json")],
        ["scan", "--output", "json", "--report-file", str(tmp_path / "same.json"),
         "--measurements-file", str(tmp_path / "same.json")],
        ["scan", "--save-snapshot", str(tmp_path / "same.json"),
         "--measurements-file", str(tmp_path / "same.json")],
        ["scan", "--measurements-file", str(tmp_path / "missing" / "new.json")],
    ]
    for args in cases:
        result = CliRunner().invoke(app, args)
        assert result.exit_code == 2, (args, result.output)
    assert destination.read_text(encoding="utf-8") == "existing"
    no_aws.assert_not_called()
