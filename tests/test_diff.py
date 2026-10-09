"""Offline comparison cannot infer resolution from missing scan coverage."""

import json
from dataclasses import replace
from datetime import datetime, timezone
from unittest.mock import Mock

from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.collectors.common import CollectionIssue, CollectionResult
from awsherlock.diff import compare_snapshots, render_diff_json
from awsherlock.models import Resource, ScanMetadata
from awsherlock.snapshot import Snapshot, write_snapshot


def sample(encrypted: bool | None, *, issue=False, region="eu-west-1", account="123456789012"):
    metadata = ScanMetadata(scan_id="sample", started_at=datetime(2026, 9, 23, tzinfo=timezone.utc),
                            account_id=account, region=region, version="test")
    resource = Resource(service="ec2", resource_type="volume", account_id=account, region=region,
                        resource_id="vol-123", resource_arn=None,
                        data={} if encrypted is None else {"encrypted": encrypted})
    issues = [CollectionIssue("vol-123", "describe_volumes", "AccessDenied")] if issue else []
    return Snapshot(metadata, {"ec2": CollectionResult([resource], issues)})


def test_new_resolved_unchanged_and_deterministic():
    unsafe, safe = sample(False), sample(True)
    assert compare_snapshots(safe, unsafe)["summary"]["NEW"] == 1
    assert compare_snapshots(unsafe, safe)["summary"]["RESOLVED"] == 1
    assert compare_snapshots(unsafe, unsafe)["summary"]["UNCHANGED"] == 1
    assert render_diff_json(compare_snapshots(unsafe, safe)) == render_diff_json(compare_snapshots(unsafe, safe))


def test_denied_or_missing_fact_cannot_resolve():
    unsafe = sample(False)
    for later in (sample(None), sample(None, issue=True)):
        result = compare_snapshots(unsafe, later)
        assert result["summary"]["UNKNOWN"] == 1
        assert result["summary"]["RESOLVED"] == 0
        assert result["coverage"]["after"]["ec2"] != "COMPLETE"


def test_prior_gap_cannot_establish_new_but_observed_finding_survives_partial_after():
    unsafe = sample(False)
    assert compare_snapshots(sample(None), unsafe)["summary"]["UNKNOWN"] == 1
    partial_unsafe = sample(False, issue=True)
    assert compare_snapshots(sample(True), partial_unsafe)["summary"]["NEW"] == 1


def test_changed_account_or_region_is_unknown():
    unsafe = sample(False)
    for later in (sample(True, region="us-east-1"), sample(True, account="999999999999")):
        result = compare_snapshots(unsafe, later)
        assert result["same_scope"] is False
        assert result["summary"]["UNKNOWN"] == 1


def test_missing_service_is_unknown():
    unsafe = sample(False)
    later = replace(unsafe, services={"s3": CollectionResult()})
    assert compare_snapshots(unsafe, later)["summary"]["UNKNOWN"] == 1


def test_cli_json_no_aws_invalid_input_and_no_leak(monkeypatch, tmp_path):
    session = Mock(side_effect=AssertionError("No AWS calls"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", session)
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    write_snapshot(sample(False), before)
    write_snapshot(sample(True), after)
    runner = CliRunner()
    result = runner.invoke(app, ["diff", str(before), str(after), "--output", "json"])
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["schema_version"] == 1 and document["kind"] == "snapshot-diff"
    assert document["changes"][0]["status"] == "RESOLVED"
    assert "evidence" not in result.stdout and "SecretAccessKey" not in result.stdout
    assert runner.invoke(app, ["diff", str(before), str(after), "--output", "xml"]).exit_code == 2
    assert runner.invoke(app, ["diff", str(before), str(tmp_path / "missing")]).exit_code == 1
    session.assert_not_called()
