"""Offline SARIF projection of synthetic scan evidence."""

import json
from dataclasses import replace
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.models import Severity
from awsherlock.sarif import SCHEMA_URI, render_sarif
from awsherlock.snapshot import write_snapshot
from test_snapshot import snapshot


def test_sarif_findings_rules_and_full_coverage(snapshot):
    report = evaluate_snapshot(snapshot)
    document = json.loads(render_sarif(report))
    assert document["$schema"] == SCHEMA_URI and document["version"] == "2.1.0"
    assert len(document["runs"]) == 1
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "AWSherlock"
    assert len(run["tool"]["driver"]["rules"]) == 42
    assert run["properties"]["coverage"] == report.coverage
    assert run["properties"]["incomplete"] is True
    assert len(run["results"]) == len(report.findings)
    first = run["results"][0]
    assert first["ruleId"] == report.findings[0].id
    assert first["level"] == "warning"
    assert first["locations"][0]["logicalLocations"][0]["name"] == report.findings[0].resource_id
    assert "physicalLocation" not in first["locations"][0]
    assert "AccessDenied" in render_sarif(report)


@pytest.mark.parametrize("severity,level", [
    (Severity.CRITICAL, "error"), (Severity.HIGH, "error"),
    (Severity.MEDIUM, "warning"), (Severity.LOW, "note"), (Severity.INFO, "note"),
])
def test_sarif_severity_mapping(snapshot, severity, level):
    report = evaluate_snapshot(snapshot)
    report.findings = [replace(report.findings[0], severity=severity)]
    result = json.loads(render_sarif(report))["runs"][0]["results"][0]
    assert result["level"] == level
    assert result["properties"]["awsherlockSeverity"] == severity.value


def test_sarif_logical_location_disambiguates_accounts_without_evidence(snapshot):
    report = evaluate_snapshot(snapshot)
    original = report.findings[0]
    report.findings = [replace(original, evidence={"secret-marker": "never export"}),
                       replace(original, account_id="999999999999", resource_arn=None,
                               evidence={"secret-marker": "never export"})]
    rendered = render_sarif(report)
    results = json.loads(rendered)["runs"][0]["results"]
    names = [result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] for result in results]
    assert names[0] != names[1]
    assert names[0].startswith(original.account_id + "/")
    assert names[1].startswith("999999999999/")
    assert "secret-marker" not in rendered and "never export" not in rendered


def test_zero_results_do_not_erase_incomplete_coverage(snapshot):
    report = evaluate_snapshot(snapshot)
    report.findings.clear()
    run = json.loads(render_sarif(report))["runs"][0]
    assert run["results"] == []
    assert run["properties"]["incomplete"] is True
    assert run["properties"]["coverage"][0]["status"] != "COMPLETE"


def test_offline_cli_sarif_stdout_file_and_no_overwrite(snapshot, monkeypatch, tmp_path):
    factory = Mock(side_effect=AssertionError("No AWS in offline SARIF"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    source = tmp_path / "snapshot.json"
    write_snapshot(snapshot, source)
    runner = CliRunner()
    stdout = runner.invoke(app, ["scan", str(source), "--output", "sarif"])
    assert stdout.exit_code == 1
    assert json.loads(stdout.stdout)["runs"][0]["properties"]["incomplete"] is True
    destination = tmp_path / "report.sarif"
    args = ["scan", str(source), "--output", "sarif", "--report-file", str(destination)]
    first = runner.invoke(app, args)
    assert first.exit_code == 1 and destination.is_file()
    saved = destination.read_bytes()
    second = runner.invoke(app, args)
    assert second.exit_code == 1 and destination.read_bytes() == saved
    factory.assert_not_called()


def test_sarif_invalid_options_and_help():
    runner = CliRunner()
    assert runner.invoke(app, ["scan", "--output", "sarif", "--summary-only"]).exit_code == 2
    assert runner.invoke(app, ["scan", "--output", "bogus"]).exit_code == 2
    help_result = runner.invoke(app, ["scan", "--help"])
    assert help_result.exit_code == 0
    assert "sarif" in help_result.output
