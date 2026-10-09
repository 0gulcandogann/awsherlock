"""Finding correlations are review hints, never inferred attack paths."""

import json
from dataclasses import replace
from datetime import datetime, timezone
from unittest.mock import Mock

from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.collectors.common import CollectionIssue, CollectionResult
from awsherlock.correlation import CorrelationError
from awsherlock.leads import investigation_leads, render_leads_json
from awsherlock.models import Resource, ScanMetadata
from awsherlock.snapshot import Snapshot, write_snapshot


def function(name="fn", *, public=True, broad=True, missing_role=False):
    arn = f"arn:aws:lambda:eu-west-1:123456789012:function:{name}"
    data = {"urls": [{"arn": arn, "auth": "NONE" if public else "AWS_IAM"}],
            "runtime": {"name": "python3.13", "deprecated": False,
                        "catalog_date": "2026-09-15", "evaluated_on": "2026-09-23"}}
    if not missing_role:
        data["role_policies"] = ["arn:aws:iam::aws:policy/AdministratorAccess"] if broad else []
    return Resource(service="lambda", resource_type="function", account_id="123456789012",
                    region="eu-west-1", resource_id=name, resource_arn=arn, data=data)


def saved(resources, issues=None):
    metadata = ScanMetadata(scan_id="lead-test", started_at=datetime(2026, 9, 23, tzinfo=timezone.utc),
                            account_id="123456789012", region="eu-west-1", version="test")
    return Snapshot(metadata, {"lambda": CollectionResult(resources, issues or [])})


def test_paired_indicators_produce_one_bounded_lead():
    document = investigation_leads(saved([function()]))
    assert document["summary"]["leads"] == 1
    lead = document["leads"][0]
    assert [item["check_id"] for item in lead["findings"]] == ["AWSH-LAMBDA-001", "AWSH-LAMBDA-002"]
    assert {item["code"] for item in lead["not_proven"]} >= {
        "ANONYMOUS_REACHABILITY_NOT_PROVEN", "ATTACK_PATH_NOT_PROVEN", "EXPLOITABILITY_NOT_PROVEN",
    }
    assert "Function URL configured without IAM authentication" in lead["why_it_matters"]
    assert "public invocation" not in lead["why_it_matters"].lower().replace("-", " ")
    assert any(item["code"] == "NETWORK_REACHABILITY_NOT_EVALUATED" for item in lead["unknown"])
    assert document["schema_version"] == 2
    assert document["incomplete"] is False
    assert "role_policies" not in render_leads_json(document)
    assert "AdministratorAccess" not in render_leads_json(document)


def test_unpaired_different_functions_and_denial_do_not_infer_lead():
    assert investigation_leads(saved([function(public=False)]))["leads"] == []
    assert investigation_leads(saved([function(broad=False)]))["leads"] == []
    split = saved([function("public", broad=False), function("broad", public=False)])
    assert investigation_leads(split)["leads"] == []
    denied = saved([function(missing_role=True)],
                   [CollectionIssue("fn", "ListAttachedRolePolicies", "AccessDenied")])
    document = investigation_leads(denied)
    assert document["leads"] == [] and document["incomplete"]
    assert document["coverage"][0]["status"] != "COMPLETE"


def test_offline_cli_json_and_bad_input(monkeypatch, tmp_path):
    session = Mock(side_effect=AssertionError("No AWS"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", session)
    path = tmp_path / "facts.json"
    write_snapshot(saved([function()]), path)
    runner = CliRunner()
    result = runner.invoke(app, ["leads", str(path), "--output", "json"])
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["summary"] == {"leads": 1, "priority": {"HIGH": 1, "MEDIUM": 0, "LOW": 0}}
    console = runner.invoke(app, ["leads", str(path)])
    assert console.exit_code == 0
    assert "LAMBDA-URL-BROAD-ROLE" in console.stdout
    assert "HIGH" in console.stdout
    assert "Function URL configured without IAM authentication" in console.stdout
    assert "public invocation" not in console.stdout.lower().replace("-", " ")
    assert runner.invoke(app, ["leads", str(path), "--output", "xml"]).exit_code == 2
    assert runner.invoke(app, ["leads", str(tmp_path / "missing")]).exit_code == 1
    session.assert_not_called()


def test_cli_reports_correlation_failure_without_traceback(monkeypatch, tmp_path):
    path = tmp_path / "facts.json"
    write_snapshot(saved([function()]), path)
    monkeypatch.setattr("awsherlock.cli.investigation_leads",
                        Mock(side_effect=CorrelationError("Correlation failed safely")))
    result = CliRunner().invoke(app, ["leads", str(path)])
    assert result.exit_code == 1
    assert "Correlation failed safely" in result.stderr
    assert "Traceback" not in result.output
