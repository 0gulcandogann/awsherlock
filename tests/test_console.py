"""Presentation preserves severity order, safe text and denied coverage."""
from dataclasses import replace
from io import StringIO
import json

import pytest
from typer.testing import CliRunner
from awsherlock.cli import app
from awsherlock.snapshot import snapshot_from_dict, write_snapshot

from rich.console import Console
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.models import Severity
from awsherlock.reporting import render_console, render_json
from test_snapshot import snapshot


def test_console_groups_results_and_keeps_denied_issues(snapshot, monkeypatch):
    report = evaluate_snapshot(snapshot)
    base = report.findings[0]
    report.findings = [replace(base, severity=Severity.LOW, title="Low priority"),
                       replace(base, severity=Severity.CRITICAL, title="Urgent priority",
                               resource_id="[red]literal-resource[/red]")]
    stdout, stderr = StringIO(), StringIO()
    monkeypatch.setattr("awsherlock.reporting.Console", lambda **kwargs: Console(
        file=stderr if kwargs.get("stderr") else stdout, width=100, color_system=None))
    render_console(report)
    text = stdout.getvalue()
    assert text.index("Urgent priority") < text.index("Low priority")
    assert "[red]literal-resource[/red]" in text
    assert "Scan coverage" in text and "Incomplete scan coverage" in text
    assert "Scan issues" in stderr.getvalue() and "AccessDenied" in stderr.getvalue()
    assert "AWSH-S3-004 requires logging" in stderr.getvalue()
    assert "check coverage:" not in text
    assert "Normalized evidence:" in text and "Risk:" in text
    assert "Remediation:" in text and "effective access was not tested" in text


def test_console_empty_narrow_output(snapshot, monkeypatch):
    snapshot.services["s3"].resources.clear()
    snapshot.services["s3"].issues.clear()
    stdout = StringIO()
    monkeypatch.setattr("awsherlock.reporting.Console", lambda **kwargs: Console(
        file=stdout, width=50, color_system=None))
    render_console(evaluate_snapshot(snapshot))
    assert "No findings were produced" in stdout.getvalue()
    assert "Incomplete scan coverage" not in stdout.getvalue()


def test_summary_only_keeps_counts_and_issues_without_cards(snapshot, monkeypatch):
    report = evaluate_snapshot(snapshot)
    stdout, stderr = StringIO(), StringIO()
    monkeypatch.setattr("awsherlock.reporting.Console", lambda **kwargs: Console(
        file=stderr if kwargs.get("stderr") else stdout, width=120, color_system=None))
    render_console(report, summary_only=True)
    text = stdout.getvalue()
    assert f"{len(report.findings)} findings" in text
    assert "Incomplete scan coverage" in text and "Scan coverage" in text
    assert report.findings[0].title not in text
    assert "Remediation:" not in text
    assert "AccessDenied" in stderr.getvalue()
    assert "Scope:" in text




@pytest.mark.parametrize('payload, visible', [
    ('\x1b[2J\x1b[H', r'\x1b[2J\x1b[H'),
    ('\x1b]8;;https://example.invalid\x1b\\link\x1b]8;;\x1b\\', r'\x1b]8;;https://example.invalid'),
    ('\x9b2J', r'\x9b2J'),
    ('\x07', r'\x07'),
    ('\rFAKE', r'\rFAKE'),
    ('\u202eFAKE\u2066', r'\u202eFAKE\u2066'),
])
def test_offline_console_escapes_controls_in_stdout_and_stderr(snapshot, monkeypatch, tmp_path, payload, visible):
    raw = snapshot.to_dict()
    raw['metadata']['region'] = 'region-' + payload
    raw['services']['s3']['resources'][0]['resource_id'] = 'bucket-' + payload
    issue = raw['services']['s3']['issues'][0]
    issue.update(resource_id='bucket-' + payload, operation='Read-' + payload,
                 message='AccessDenied: ' + payload)
    hostile = snapshot_from_dict(raw)
    path = tmp_path / 'hostile.json'
    write_snapshot(hostile, path)
    monkeypatch.setattr('awsherlock.cli.create_scan_context', lambda **kwargs: pytest.fail('Offline scan must not create AWS session'))
    result = CliRunner().invoke(app, ['scan', str(path)], terminal_width=200, color=False)
    assert result.exit_code == 1
    assert payload not in result.stdout and payload not in result.stderr
    assert visible in result.stdout and visible in result.stderr
    assert 'AccessDenied' in result.stderr
    assert 'Incomplete scan coverage' in result.stdout
    # Terminal escaping does not rewrite stored facts or JSON report values.
    saved = json.loads(render_json(evaluate_snapshot(hostile)))
    assert saved['findings'][0]['resource_id'] == 'bucket-' + payload
    assert hostile.to_dict() == raw


def test_console_keeps_generated_colors_and_readable_multiline_text(snapshot, monkeypatch):
    report = evaluate_snapshot(snapshot)
    base = report.findings[0]
    report.findings = [replace(base, title='Title\x1b[2J',
                              description='First line\nSecond line\x1b[2J',
                              remediation='Step one\n\tStep two\x1b]0;title\x07',
                              risk='Risk\x1b[2J', evidence={'fact': 'observed\x1b[2J'})]
    report.metadata['accounts'] = [{'account_id': '000000000001', 'name': 'Name\x1b[2J',
                                   'state': 'ACTIVE', 'scan_status': 'PARTIAL'}]
    stdout, stderr = StringIO(), StringIO()
    monkeypatch.setattr('awsherlock.reporting.Console', lambda **kwargs: Console(
        file=stderr if kwargs.get('stderr') else stdout, width=180, force_terminal=True,
        color_system='standard', legacy_windows=False))
    render_console(report)
    text = stdout.getvalue()
    assert '\x1b[' in text  # Rich-generated color escapes remain enabled.
    assert '\x1b[2J' not in text and '\x1b]0;' not in text
    assert r'Title\x1b[2J' in text and r'Name\x1b[2J' in text
    assert 'First line' in text and 'Second line' in text
    assert r'First line\nSecond line' not in text
    assert 'Step two' in text
    assert r'Risk\x1b[2J' in text and r'observed\u001b[2J' in text


def test_scalar_newlines_cannot_create_fake_resource_lines(snapshot, monkeypatch):
    report = evaluate_snapshot(snapshot)
    report.findings[0] = replace(report.findings[0], resource_id='bucket\nFAKE PASS')
    stdout = StringIO()
    monkeypatch.setattr('awsherlock.reporting.Console', lambda **kwargs: Console(file=stdout, width=150, color_system=None))
    render_console(report)
    assert r'Resource: bucket\nFAKE PASS' in stdout.getvalue()
    assert 'bucket\nFAKE PASS' not in stdout.getvalue()


def test_cli_escapes_controls_in_saved_report_path(snapshot, monkeypatch, tmp_path):
    source = tmp_path / 'snapshot.json'
    write_snapshot(snapshot, source)
    path = 'report-\x1b[2J.html'
    monkeypatch.setattr('awsherlock.cli.write_report', lambda *args: None)
    result = CliRunner().invoke(app, ['scan', str(source), '--output', 'html', '--report-file', path])
    assert result.exit_code == 1
    assert '\x1b[2J' not in result.output
    assert r'report-\x1b[2J.html' in result.output
