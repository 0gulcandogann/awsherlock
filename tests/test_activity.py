"""Percentage progress follows completed work and preserves report output."""

from contextlib import contextmanager
from io import StringIO
import json
from unittest.mock import Mock

import pytest
from rich.console import Console
from rich.progress import Task
from typer.testing import CliRunner

from awsherlock.activity import ASCIIBarColumn, scan_activity
from awsherlock.cli import app
from awsherlock.collectors.common import CollectionIssue, CollectionResult
from awsherlock.snapshot import SnapshotError, capture_snapshot, write_snapshot
from test_s3 import context
from test_snapshot import snapshot


@pytest.mark.parametrize("percent,filled", [(0, 0), (25, 5), (40, 8), (100, 20)])
def test_loading_bar_uses_only_ascii(percent, filled):
    text = ASCIIBarColumn().render(Task(0, "scan", 100, percent, lambda: 0)).plain
    assert text == "[" + "#" * filled + "-" * (20 - filled) + "]"
    assert text.isascii()


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt])
def test_banner_then_percentage_and_cursor_restoration(monkeypatch, failure):
    stream = StringIO()
    console = Console(file=stream, force_terminal=True, force_interactive=True,
                      width=100, legacy_windows=False, _environ={"TERM": "xterm"})
    monkeypatch.setattr("awsherlock.activity.Console", lambda **kwargs: console)
    monkeypatch.setattr("awsherlock.activity.terminal_banner", lambda **kwargs: "ASCII LOGO")
    def run():
        with scan_activity() as update:
            update("Scanning S3", 1, 4)
            if failure:
                raise failure()
            update("Scan finished", 4, 4)
    if failure:
        with pytest.raises(failure):
            run()
    else:
        run()
    output = stream.getvalue()
    assert output.count("ASCII LOGO") == 1
    assert output.index("ASCII LOGO") < output.index("25%")
    assert ("100%" in output) == (failure is None)
    assert "\x1b[?1049" not in output
    assert "\x1b[?25h" in output
    console.print("Report ready")
    assert stream.getvalue().endswith("Report ready\n")


@pytest.mark.parametrize("dumb", [False, True])
def test_redirected_and_dumb_terminal_have_no_progress(monkeypatch, dumb):
    stream = StringIO()
    console = Console(file=stream, force_terminal=dumb,
                      _environ={"TERM": "dumb"} if dumb else {})
    monkeypatch.setattr("awsherlock.activity.Console", lambda **kwargs: console)
    with scan_activity() as update:
        update("Scanning S3", 1, 4)
        update("Scan finished", 4, 4)
    assert stream.getvalue() == ""


@pytest.fixture
def recorded_progress(monkeypatch):
    events = []
    @contextmanager
    def activity(**kwargs):
        yield lambda stage, completed, total: events.append((stage, completed, total))
    monkeypatch.setattr("awsherlock.cli.scan_activity", activity)
    return events


@pytest.mark.parametrize("dumb", [False, True])
def test_verbose_without_progress_escapes_stage_controls(monkeypatch, dumb):
    stream = StringIO()
    console = Console(file=stream, force_terminal=dumb, width=200,
                      _environ={"TERM": "dumb"} if dumb else {})
    monkeypatch.setattr("awsherlock.activity.Console", lambda **kwargs: console)
    with scan_activity(enabled=False, verbose=True) as update:
        update("Scanning S3\x1b[2J", 1, 4)
    assert "[scan] Scanning S3\\x1b[2J (1/4 work units)" in stream.getvalue()
    assert "\x1b[2J" not in stream.getvalue()
    assert "[#####" not in stream.getvalue()


@pytest.mark.parametrize("denied", [False, True])
def test_cli_percentage_follows_service_completion(context, monkeypatch, recorded_progress, denied):
    monkeypatch.setattr("awsherlock.cli.create_scan_context", lambda **kwargs: context)
    def collect(ctx):
        assert recorded_progress[-1] == ("Scanning S3", 1, 3)
        issues = [CollectionIssue(None, "ListBuckets", "AccessDenied")] if denied else []
        return CollectionResult([], issues)
    monkeypatch.setattr("awsherlock.snapshot.service_components", lambda service: (collect, []))
    result = CliRunner().invoke(app, ["scan", "--services", "s3", "--output", "json"])
    assert result.exit_code == int(denied)
    data = json.loads(result.stdout)
    assert data["coverage"][0]["status"] == ("ACCESS_DENIED" if denied else "COMPLETE")
    assert recorded_progress[:3] == [
        ("Connecting to AWS", 0, 3), ("Collecting AWS resources", 1, 3), ("Scanning S3", 1, 3),
    ]
    assert recorded_progress[3:5] == [("Collected S3", 2, 3), ("Evaluating security checks", 2, 3)]
    assert recorded_progress[-1][1:] == (1, 1)
    if denied:
        assert "incomplete coverage" in recorded_progress[-1][0]


def test_failed_collection_does_not_reach_100(context, monkeypatch, recorded_progress):
    monkeypatch.setattr("awsherlock.cli.create_scan_context", lambda **kwargs: context)
    collector = Mock(side_effect=SnapshotError("Collection failed"))
    monkeypatch.setattr("awsherlock.snapshot.service_components", lambda service: (collector, []))
    result = CliRunner().invoke(app, ["scan", "--services", "s3"])
    assert result.exit_code == 1
    assert "Collection failed" in result.stderr
    assert all(completed < total for _, completed, total in recorded_progress)


@pytest.mark.parametrize("stage", ["authentication", "evaluation"])
def test_failed_authentication_or_evaluation_does_not_finish(context, monkeypatch, recorded_progress, stage):
    from awsherlock.aws.session import SessionError
    factory = Mock(return_value=context)
    if stage == "authentication":
        factory.side_effect = SessionError("AccessDenied")
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", Mock())
    monkeypatch.setattr("awsherlock.cli.evaluate_snapshot", Mock(side_effect=SnapshotError("Evaluation failed")))
    result = CliRunner().invoke(app, ["scan", "--services", "s3"])
    assert result.exit_code == 1
    assert all(completed < total for _, completed, total in recorded_progress)


def test_interactive_json_keeps_banner_and_progress_on_stderr(context, monkeypatch):
    stderr = StringIO()
    console = Console(file=stderr, force_terminal=True, force_interactive=True,
                      width=100, legacy_windows=False, _environ={"TERM": "xterm"})
    monkeypatch.setattr("awsherlock.activity.Console", lambda **kwargs: console)
    monkeypatch.setattr("awsherlock.activity.terminal_banner", lambda **kwargs: "ASCII LOGO")
    monkeypatch.setattr("awsherlock.cli.create_scan_context", lambda **kwargs: context)
    monkeypatch.setattr("awsherlock.snapshot.service_components",
                        lambda service: (lambda ctx: CollectionResult([], []), []))
    result = CliRunner().invoke(app, ["scan", "--services", "s3", "--output", "json"])
    assert result.exit_code == 0
    json.loads(result.stdout)
    assert "ASCII LOGO" not in result.stdout
    assert "ASCII LOGO" in stderr.getvalue() and "100%" in stderr.getvalue()


def test_offline_progress_finishes_after_evaluation(snapshot, tmp_path, recorded_progress):
    path = tmp_path / "snapshot.json"
    write_snapshot(snapshot, path)
    result = CliRunner().invoke(app, ["scan", str(path), "--output", "json"])
    assert result.exit_code == 1  # fixture has incomplete coverage
    json.loads(result.stdout)
    assert [event[1:] for event in recorded_progress] == [(0, 2), (1, 2), (1, 1)]


def test_snapshot_callback_reports_completed_collectors(context, monkeypatch):
    events = []
    def collect(ctx):
        assert events[-1][0].startswith("Scanning ")
        return CollectionResult([], [])
    monkeypatch.setattr("awsherlock.snapshot.service_components", lambda service: (collect, []))
    capture_snapshot(context, ["iam", "s3"], progress=lambda *event: events.append(event))
    assert events == [("Scanning IAM", 0, 2), ("Collected IAM", 1, 2),
                      ("Scanning S3", 1, 2), ("Collected S3", 2, 2)]


def test_organization_progress_counts_failed_and_skipped_accounts(context, monkeypatch, recorded_progress):
    from awsherlock.aws.session import SessionError
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = [
        {"Accounts": [{"Id": "000000000001", "Name": "Closed", "State": "CLOSED"},
                      {"Id": "000000000002", "Name": "Denied", "State": "ACTIVE"}]}]
    monkeypatch.setattr("awsherlock.cli.create_scan_context", lambda **kwargs: context)
    monkeypatch.setattr("awsherlock.organization.create_scan_context", Mock(side_effect=SessionError("AccessDenied")))
    result = CliRunner().invoke(app, ["scan", "organization", "--services", "s3", "--output", "json"])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert [entry["status"] for entry in data["coverage"]] == ["NOT_SCANNED", "ACCESS_DENIED"]
    percentages = [completed / total for _, completed, total in recorded_progress]
    assert percentages == sorted(percentages)
    assert ("Accounts discovered", 2, 5) in recorded_progress
    assert ("Account 000000000001 skipped", 3, 5) in recorded_progress
    assert ("Account 000000000002 unavailable", 4, 5) in recorded_progress
    assert percentages[-1] == 1
