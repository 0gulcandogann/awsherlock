"""Exact local suppressions retain findings and coverage."""

import json
from datetime import date
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.reporting import render_html
from awsherlock.snapshot import write_snapshot
from awsherlock.suppressions import SuppressionError, apply_suppressions, read_suppressions
from test_diff import sample


def entry(**changes):
    result = {"check_id": "AWSH-EC2-006", "account_id": "123456789012", "region": "eu-west-1",
              "resource_id": "vol-123", "owner": "platform", "reason": "Tracked exception",
              "expires_on": "2099-01-01"}
    result.update(changes)
    return result


def test_active_expired_unmatched_and_coverage():
    report = evaluate_snapshot(sample(False, issue=True))
    original_coverage = list(report.coverage)
    apply_suppressions(report, [entry(), entry(resource_id="vol-other"),
                                entry(resource_id="vol-expired", expires_on="2000-01-01")],
                       today=date(2026, 9, 23))
    data = report.to_dict()
    assert data["summary"]["findings"] == 1
    assert data["summary"]["suppressed"] == 1
    assert data["summary"]["expired_suppressions"] == 1
    assert [item["status"] for item in data["suppressions"]] == ["APPLIED", "UNMATCHED", "EXPIRED"]
    assert data["findings"][0]["suppression"]["owner"] == "platform"
    assert data["coverage"] == original_coverage and data["summary"]["incomplete"]
    assert "Suppression audit" in render_html(report)
    assert "Tracked exception" in render_html(report)


def test_expired_and_cross_scope_do_not_suppress():
    report = evaluate_snapshot(sample(False))
    apply_suppressions(report, [entry(expires_on="2000-01-01"),
                                entry(account_id="999999999999"), entry(region="us-east-1")],
                       today=date(2026, 9, 23))
    assert report.to_dict()["summary"]["suppressed"] == 0
    assert "suppression" not in report.to_dict()["findings"][0]


@pytest.mark.parametrize("change", [
    {"check_id": []}, {"account_id": "bad"}, {"expires_on": "2099-02-31"},
    {"owner": ""}, {"reason": ""}, {"resource_id": ""}, {"region": 42},
])
def test_invalid_entries_fail_without_echoing_values(tmp_path, change):
    path = tmp_path / "suppressions.json"
    path.write_text(json.dumps({"schema_version": 1, "suppressions": [entry(**change)]}), encoding="utf-8")
    with pytest.raises(SuppressionError):
        read_suppressions(path)


def test_duplicate_json_and_identity_rejected(tmp_path):
    path = tmp_path / "suppressions.json"
    path.write_text('{"schema_version":1,"schema_version":1,"suppressions":[]}', encoding="utf-8")
    with pytest.raises(SuppressionError, match="Duplicate"):
        read_suppressions(path)
    path.write_text(json.dumps({"schema_version": 1, "suppressions": [entry(), entry()]}), encoding="utf-8")
    with pytest.raises(SuppressionError, match="Duplicate"):
        read_suppressions(path)


def test_offline_cli_json_preserves_findings_no_aws(monkeypatch, tmp_path):
    session = Mock(side_effect=AssertionError("No AWS calls"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", session)
    snapshot_path = tmp_path / "facts.json"
    suppressions_path = tmp_path / "suppressions.json"
    write_snapshot(sample(False), snapshot_path)
    suppressions_path.write_text(json.dumps({"schema_version": 1, "suppressions": [entry()]}), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(snapshot_path), "--output", "json",
                                 "--suppressions-file", str(suppressions_path)])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert len(data["findings"]) == 1 and data["summary"]["suppressed"] == 1
    assert "SecretAccessKey" not in result.stdout
    assert runner.invoke(app, ["scan", str(snapshot_path), "--output", "sarif",
                               "--suppressions-file", str(suppressions_path)]).exit_code == 2
    session.assert_not_called()
