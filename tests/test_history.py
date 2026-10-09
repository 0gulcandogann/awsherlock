"""Observed timestamps require explicit, ordered snapshot inputs."""

import json
from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.history import HistoryError, finding_history, render_history_json
from awsherlock.snapshot import write_snapshot
from test_diff import sample


def later(snapshot, *, scan_id="second"):
    return replace(snapshot, metadata=replace(snapshot.metadata, scan_id=scan_id,
                                              started_at=snapshot.metadata.started_at + timedelta(days=1)))


def test_first_last_observed_and_coverage_without_resolution_claim():
    first = sample(False)
    second = later(sample(None, issue=True))
    result = finding_history([first, second])
    assert result["schema_version"] == 1 and result["kind"] == "finding-history"
    assert result["incomplete"] is True
    assert result["scans"][1]["coverage"]["ec2"] != "COMPLETE"
    finding = result["findings"][0]
    assert finding["first_scan_id"] == finding["last_scan_id"] == "sample"
    assert finding["observed_scan_count"] == 1
    assert "resolved" not in render_history_json(result).lower()
    assert "evidence" not in render_history_json(result).lower()


def test_multiple_observations_and_zero_findings():
    first = sample(False)
    second = later(sample(False))
    result = finding_history([first, second])
    assert result["findings"][0]["last_scan_id"] == "second"
    assert result["findings"][0]["observed_scan_count"] == 2
    assert finding_history([sample(True), later(sample(True))])["findings"] == []


@pytest.mark.parametrize("snapshots", [
    [sample(False)],
    [sample(False), sample(False)],
    [sample(False), later(sample(False, region="us-east-1"))],
    [sample(False), later(sample(False, account="999999999999"))],
])
def test_invalid_history_scope_or_order(snapshots):
    with pytest.raises(HistoryError):
        finding_history(snapshots)


def test_offline_cli_json_no_aws_and_invalid_inputs(monkeypatch, tmp_path):
    session = Mock(side_effect=AssertionError("History must not contact AWS"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", session)
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    write_snapshot(sample(False), before)
    write_snapshot(later(sample(True)), after)
    runner = CliRunner()
    result = runner.invoke(app, ["history", str(before), str(after), "--output", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["findings"][0]["first_scan_id"] == "sample"
    assert "SecretAccessKey" not in result.stdout
    assert runner.invoke(app, ["history", str(before)]).exit_code == 2
    assert runner.invoke(app, ["history", str(before), str(after), "--output", "xml"]).exit_code == 2
    assert runner.invoke(app, ["history", str(before), str(tmp_path / "missing")]).exit_code == 1
    session.assert_not_called()
