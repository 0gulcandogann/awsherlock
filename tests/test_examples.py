import json
from pathlib import Path
from unittest.mock import Mock

from typer.testing import CliRunner
from awsherlock.cli import app
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.reporting import render_html
from awsherlock.snapshot import read_snapshot

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_demo_reports_match_snapshot(monkeypatch, tmp_path):
    source = EXAMPLES / "demo-snapshot.json"
    report = evaluate_snapshot(read_snapshot(source))
    assert json.loads((EXAMPLES / "demo-report.json").read_text(encoding="utf-8")) == report.to_dict()
    assert (EXAMPLES / "demo-report.html").read_text(encoding="utf-8") == render_html(report)
    assert report.metadata["account_id"] == "000000000000"
    assert len(report.findings) == 4
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(side_effect=AssertionError("Demo is offline")))
    for options in ([], ["--output", "json"], ["--output", "html", "--report-file", str(tmp_path / "demo.html")]):
        result = CliRunner().invoke(app, ["scan", str(source), *options])
        assert result.exit_code == 1
        assert "Invalid" not in result.output
    assert (tmp_path / "demo.html").is_file()
