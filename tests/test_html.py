from dataclasses import replace
from html.parser import HTMLParser
from unittest.mock import Mock
import pytest
from typer.testing import CliRunner
from awsherlock.cli import app
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.reporting import render_html
from awsherlock.snapshot import write_snapshot
from test_snapshot import snapshot


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def test_html_self_contained_and_escaped(snapshot):
    report = evaluate_snapshot(snapshot)
    report.findings[0] = replace(report.findings[0], title='<img src=x onerror="alert(1)">',
                                 evidence={"test": "</pre><script>alert(1)</script>"})
    html = render_html(report)
    assert "&lt;img" in html
    assert "<script>alert(1)</script>" not in html
    assert "Incomplete scan coverage" in html
    assert "AWSH-S3-001" in html
    assert "Remediation" in html and "Evidence" in html
    assert "hero-stamp" in html and "severity-track" in html
    parsed = Elements()
    parsed.feed(html)
    assert not any(tag in {"img", "iframe", "link"} for tag, attrs in parsed.tags)
    assert not any("src" in attrs for tag, attrs in parsed.tags)


def test_html_empty(snapshot):
    snapshot.services["s3"].resources.clear()
    snapshot.services["s3"].issues.clear()
    html = render_html(evaluate_snapshot(snapshot))
    assert "No findings were produced" in html


def test_html_cli_offline(snapshot, monkeypatch, tmp_path):
    path = tmp_path / "snapshot.json"
    output = tmp_path / "report.html"
    write_snapshot(snapshot, path)
    factory = Mock(side_effect=AssertionError("No AWS session for HTML from snapshot"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    result = CliRunner().invoke(app, ["scan", str(path), "--output", "html", "--report-file", str(output)])
    assert result.exit_code == 1
    assert output.read_text(encoding="utf-8").startswith("<!doctype html>")
    factory.assert_not_called()
