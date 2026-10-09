"""The standalone identity view is an offline projection of saved IAM facts."""

import json
from dataclasses import replace
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.snapshot import capture_snapshot, write_snapshot
from test_identity import identity_context, snapshot_at
from test_s3 import context as s3_context
from test_iam import context as iam_context


def forbid_aws_and_writes(monkeypatch):
    authentication = Mock(side_effect=AssertionError("view must not authenticate"))
    collector = Mock(side_effect=AssertionError("view must not collect"))
    writer = Mock(side_effect=AssertionError("view must not write"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", authentication)
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", collector)
    monkeypatch.setattr("awsherlock.cli.write_report", writer)
    monkeypatch.setattr("awsherlock.cli.write_snapshot", writer)
    return authentication, collector, writer


def test_complete_console_and_json_view(identity_context, monkeypatch, tmp_path):
    snapshot = snapshot_at(identity_context[0])
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    guards = forbid_aws_and_writes(monkeypatch)
    runner = CliRunner()
    console = runner.invoke(app, ["identities", str(path), "--color", "never"])
    assert console.exit_code == 0
    assert "Identity governance" in console.output
    assert "worker" in console.output and "integration" in console.output
    assert "COMPLETE" in console.output
    result = runner.invoke(app, ["identities", str(path), "--output", "json"])
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert set(document) == {"schema_version", "kind", "account_id", "coverage", "identities"}
    assert document["schema_version"] == 1 and document["kind"] == "identity-view"
    assert len(document["identities"]) == 2
    assert document["coverage"][0]["status"] == "COMPLETE"
    assert path.read_text(encoding="utf-8")
    for guard in guards:
        guard.assert_not_called()


def test_empty_iam_snapshot_has_explicit_empty_state(identity_context, monkeypatch, tmp_path):
    snapshot = snapshot_at(identity_context[0])
    snapshot.services["iam"].resources.clear()
    path = tmp_path / "empty.json"
    write_snapshot(snapshot, path)
    forbid_aws_and_writes(monkeypatch)
    result = CliRunner().invoke(app, ["identities", str(path), "--color", "never"])
    assert result.exit_code == 0
    assert "No IAM role/user identities were discovered" in result.output
    assert "COMPLETE" in result.output


def test_old_iam_snapshot_keeps_unknown_evidence_incomplete(iam_context, monkeypatch, tmp_path):
    snapshot = capture_snapshot(iam_context, ["iam"])
    path = tmp_path / "old.json"
    write_snapshot(snapshot, path)
    forbid_aws_and_writes(monkeypatch)
    result = CliRunner().invoke(app, ["identities", str(path), "--output", "json"])
    assert result.exit_code == 1
    document = json.loads(result.stdout)
    assert document["coverage"][0]["status"] != "COMPLETE"
    assert document["identities"]
    assert "identity_profile" in document["identities"][0]["missing_facts"]
    assert "synthetic-key-marker" not in result.stdout


def test_missing_iam_service_and_invalid_inputs_fail_before_aws(s3_context, monkeypatch, tmp_path):
    snapshot = capture_snapshot(s3_context, ["s3"])
    path = tmp_path / "s3.json"
    write_snapshot(snapshot, path)
    guards = forbid_aws_and_writes(monkeypatch)
    runner = CliRunner()
    missing_iam = runner.invoke(app, ["identities", str(path)])
    assert missing_iam.exit_code == 1 and "no IAM collection" in missing_iam.output
    bad_format = runner.invoke(app, ["identities", str(path), "--output", "html"])
    assert bad_format.exit_code == 2
    missing_file = runner.invoke(app, ["identities", str(tmp_path / "missing.json")])
    assert missing_file.exit_code == 1 and "Could not read" in missing_file.output
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not-json", encoding="utf-8")
    invalid = runner.invoke(app, ["identities", str(malformed)])
    assert invalid.exit_code == 1 and "Invalid snapshot JSON" in invalid.output
    for guard in guards:
        guard.assert_not_called()


def test_console_escapes_identity_names(identity_context, monkeypatch, tmp_path):
    snapshot = snapshot_at(identity_context[0])
    original = snapshot.services["iam"].resources[0]
    snapshot.services["iam"].resources[0] = replace(original, resource_id="worker\x1b[31m")
    path = tmp_path / "control.json"
    write_snapshot(snapshot, path)
    forbid_aws_and_writes(monkeypatch)
    result = CliRunner().invoke(app, ["identities", str(path), "--color", "never"])
    assert result.exit_code == 0
    assert "\x1b" not in result.output


def test_help_describes_offline_view():
    result = CliRunner().invoke(app, ["identities", "--help"])
    assert result.exit_code == 0
    assert "without AWS calls" in result.output
    assert "--output" in result.output
    assert "--view" in result.output


@pytest.mark.parametrize("view,fact,field,value", [
    ("ai", "identity_approval", "declared_kind", "ai"),
    ("unowned", "identity_profile", "owner", False),
    ("stale", "identity_usage", "last_used_days", 91),
    ("shared", "identity_approval", "shared", True),
])
def test_filtered_views_are_evidence_backed(identity_context, monkeypatch, tmp_path, view, fact, field, value):
    snapshot = snapshot_at(identity_context[0])
    role = next(item for item in snapshot.services["iam"].resources if item.resource_type == "role")
    role.data[fact][field] = value
    if view == "unowned":
        role.data["identity_approval"]["owner"] = False
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    guards = forbid_aws_and_writes(monkeypatch)
    runner = CliRunner()
    result = runner.invoke(app, ["identities", str(path), "--view", view, "--output", "json"])
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["schema_version"] == 2 and document["view"] == view
    assert document["total_identities"] == 2 and document["matched_identities"] == 1
    assert [item["name"] for item in document["identities"]] == ["worker"]
    assert document["coverage"][0]["status"] == "COMPLETE"
    console = runner.invoke(app, ["identities", str(path), "--view", view, "--color", "never"])
    assert console.exit_code == 0
    assert "1 of 2 identities matched" in console.output
    assert "worker" in console.output and "integration" not in console.output
    assert "COMPLETE" in console.output
    for guard in guards:
        guard.assert_not_called()


@pytest.mark.parametrize("view", ["ai", "unowned", "stale", "shared"])
def test_empty_filtered_views_are_not_safety_claims(identity_context, monkeypatch, tmp_path, view):
    snapshot = snapshot_at(identity_context[0])
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    forbid_aws_and_writes(monkeypatch)
    result = CliRunner().invoke(app, ["identities", str(path), "--view", view, "--color", "never"])
    assert result.exit_code == 0
    assert "0 of 2 identities matched" in result.output
    assert "No match does not prove" in result.output
    assert "COMPLETE" in result.output


@pytest.mark.parametrize("view", ["ai", "unowned", "stale", "shared"])
def test_old_snapshot_unknown_evidence_stays_incomplete(iam_context, monkeypatch, tmp_path, view):
    snapshot = capture_snapshot(iam_context, ["iam"])
    path = tmp_path / "old.json"
    write_snapshot(snapshot, path)
    forbid_aws_and_writes(monkeypatch)
    result = CliRunner().invoke(app, ["identities", str(path), "--view", view, "--output", "json"])
    assert result.exit_code == 1
    document = json.loads(result.stdout)
    assert document["matched_identities"] == 0
    assert document["total_identities"] > 0
    assert document["coverage"][0]["status"] != "COMPLETE"


def test_bad_view_fails_before_snapshot_or_aws(identity_context, monkeypatch, tmp_path):
    guards = forbid_aws_and_writes(monkeypatch)
    result = CliRunner().invoke(app, ["identities", str(tmp_path / "missing.json"), "--view", "guess"])
    assert result.exit_code == 2
    assert "Use all, ai, unowned, stale or shared" in result.output
    for guard in guards:
        guard.assert_not_called()
