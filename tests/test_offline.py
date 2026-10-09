from unittest.mock import Mock
import json
import pytest
from typer.testing import CliRunner
from awsherlock.cli import app
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.snapshot import capture_snapshot, read_snapshot, write_snapshot, SnapshotError, snapshot_from_dict
from awsherlock.reporting import render_json
from test_s3 import context
from test_snapshot import snapshot


def test_live_offline_parity(context, tmp_path):
    live = capture_snapshot(context, ["s3"])
    assert live.schema_version == 2
    assert live.supports_relationships
    path = tmp_path / "snapshot.json"
    write_snapshot(live, path)
    assert render_json(evaluate_snapshot(live)) == render_json(evaluate_snapshot(read_snapshot(path)))


def test_offline_cli_without_aws(snapshot, monkeypatch, tmp_path):
    factory = Mock(side_effect=AssertionError("Offline scan must not create a session"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    path = tmp_path / "snapshot.json"
    write_snapshot(snapshot, path)
    result = CliRunner().invoke(app, ["scan", str(path), "--output", "json"])
    assert result.exit_code == 1  # Partial collection retained, never silently PASS.
    data = json.loads(result.stdout)
    assert set(data) == {"metadata", "coverage", "findings", "summary"}
    assert data["findings"][0]["id"] == "AWSH-S3-001"
    assert data["summary"]["incomplete"]
    assert data["coverage"][0]["issues"][0]["message"] == "AccessDenied"
    factory.assert_not_called()


def test_v2_offline_cli_with_empty_relationships_does_not_call_aws(snapshot, monkeypatch, tmp_path):
    factory = Mock(side_effect=AssertionError("Offline scan must not create a session"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    snapshot.schema_version = 2
    path = tmp_path / "snapshot-v2.json"
    write_snapshot(snapshot, path)
    result = CliRunner().invoke(app, ["scan", str(path), "--output", "json"])
    assert result.exit_code == 1
    assert read_snapshot(path).supports_relationships
    factory.assert_not_called()


def test_live_json_clean_stdout(context, monkeypatch):
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    result = CliRunner().invoke(app, ["scan", "--services", "s3", "--output", "json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["summary"]["findings"] == 0


def test_json_file_and_no_overwrite(context, monkeypatch, tmp_path):
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    path = tmp_path / "report.json"
    args = ["scan", "--services", "s3", "--output", "json", "--report-file", str(path)]
    assert CliRunner().invoke(app, args).exit_code == 0
    original = path.read_bytes()
    assert CliRunner().invoke(app, args).exit_code == 1
    assert path.read_bytes() == original


def test_malformed_fact_is_not_pass(snapshot):
    data = snapshot.to_dict()
    data["services"]["s3"]["resources"][0]["data"]["public_access_block"] = {"BlockPublicAcls": "true"}
    with pytest.raises(SnapshotError):
        snapshot_from_dict(data)


def test_missing_facts_without_issues_stays_incomplete(snapshot):
    snapshot.services["s3"].resources[0].data.clear()
    snapshot.services["s3"].issues.clear()
    result = evaluate_snapshot(snapshot)
    assert result.incomplete
    assert result.coverage[0]["status"] == "NOT_SCANNED"


def test_offline_rejects_auth_and_missing_files(monkeypatch, tmp_path):
    factory = Mock(side_effect=AssertionError("No AWS"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    path = str(tmp_path / "missing.json")
    assert CliRunner().invoke(app, ["scan", path, "--profile", "test"]).exit_code == 2
    assert CliRunner().invoke(app, ["scan", path]).exit_code == 1
    factory.assert_not_called()
