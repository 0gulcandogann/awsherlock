"""Automation exits distinguish risk from incomplete evidence."""

import json
from unittest.mock import Mock

from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.snapshot import write_snapshot
from test_diff import sample
from test_suppressions import entry


def paths(tmp_path, before, after):
    earlier, later = tmp_path / "before.json", tmp_path / "after.json"
    write_snapshot(before, earlier)
    write_snapshot(after, later)
    return str(earlier), str(later)


def test_scan_high_critical_incomplete_and_default(monkeypatch, tmp_path):
    blocked = Mock(side_effect=AssertionError("No AWS"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", blocked)
    unsafe, safe = paths(tmp_path, sample(False), sample(True))
    runner = CliRunner()
    assert runner.invoke(app, ["scan", unsafe, "--output", "json"]).exit_code == 0
    high = runner.invoke(app, ["scan", unsafe, "--output", "json", "--fail-on", "high"])
    assert high.exit_code == 3 and json.loads(high.stdout)["summary"]["findings"] == 1
    assert runner.invoke(app, ["scan", unsafe, "--fail-on", "critical"]).exit_code == 0
    assert runner.invoke(app, ["scan", safe, "--fail-on", "high"]).exit_code == 0
    assert runner.invoke(app, ["scan", unsafe, "--fail-on", "new"]).exit_code == 2
    blocked.assert_not_called()


def test_incomplete_precedes_threshold_and_active_suppression(tmp_path):
    runner = CliRunner()
    partial, _ = paths(tmp_path, sample(False, issue=True), sample(True))
    assert runner.invoke(app, ["scan", partial, "--fail-on", "high"]).exit_code == 1
    suppression = tmp_path / "suppressions.json"
    suppression.write_text(json.dumps({"schema_version": 1, "suppressions": [entry()]}), encoding="utf-8")
    assert runner.invoke(app, ["scan", partial, "--fail-on", "high", "--suppressions-file", str(suppression)]).exit_code == 1
    complete = tmp_path / "complete.json"
    write_snapshot(sample(False), complete)
    assert runner.invoke(app, ["scan", str(complete), "--fail-on", "high",
                               "--suppressions-file", str(suppression)]).exit_code == 0


def test_diff_new_and_unknown_precedence(tmp_path):
    runner = CliRunner()
    safe, unsafe = paths(tmp_path, sample(True), sample(False))
    assert runner.invoke(app, ["diff", safe, unsafe, "--fail-on", "new", "--output", "json"]).exit_code == 3
    assert runner.invoke(app, ["diff", unsafe, safe, "--fail-on", "new"]).exit_code == 0
    assert runner.invoke(app, ["diff", safe, unsafe, "--fail-on", "high"]).exit_code == 2
    incomplete = tmp_path / "incomplete.json"
    write_snapshot(sample(None), incomplete)
    assert runner.invoke(app, ["diff", str(incomplete), unsafe, "--fail-on", "new"]).exit_code == 1
    assert runner.invoke(app, ["diff", str(incomplete), unsafe]).exit_code == 0
