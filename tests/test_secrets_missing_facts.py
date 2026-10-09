"""Secrets Manager missing-fact coverage stays specific, safe and offline-capable."""

import json
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.collectors.common import CollectionIssue
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.snapshot import capture_snapshot, read_snapshot, write_snapshot
from test_s3 import aws_error
from test_serverless import context


FACT_OPERATIONS = (
    ("rotation", "RotationMetadata", "AWSH-SECRET-001"),
    ("policy", "GetResourcePolicy", "AWSH-SECRET-002"),
    ("encryption", "DescribeKey", "AWSH-SECRET-003"),
)


@pytest.mark.parametrize("fact,operation,check_id", FACT_OPERATIONS)
def test_related_denial_names_only_check_fact_and_safe_reason(context, fact, operation, check_id):
    snapshot = capture_snapshot(context, ["secretsmanager"])
    snapshot.services["secretsmanager"].resources[0].data.pop(fact)
    snapshot.services["secretsmanager"].issues.append(
        CollectionIssue("test-secret", operation, "AccessDenied: private-marker"))
    coverage = evaluate_snapshot(snapshot).coverage[0]
    required = [issue for issue in coverage["issues"] if issue["operation"] == "RequiredFact"]
    assert required == [{"resource_id": "test-secret", "operation": "RequiredFact",
                         "message": f"{check_id} requires {fact}; a related collection issue is recorded separately."}]
    assert "private-marker" not in required[0]["message"]
    assert coverage["status"] == "PARTIAL"
    assert coverage["evaluated"] == 2 and coverage["not_scanned"] == 1


@pytest.mark.parametrize("fact,operation,check_id", FACT_OPERATIONS)
def test_unrelated_issue_does_not_claim_related_failure(context, tmp_path, fact, operation, check_id):
    snapshot = capture_snapshot(context, ["secretsmanager"])
    snapshot.services["secretsmanager"].resources[0].data.pop(fact)
    snapshot.services["secretsmanager"].issues.extend([
        CollectionIssue("different-secret", operation, "AccessDenied"),
        CollectionIssue("test-secret", "OtherRead", "AccessDenied"),
    ])
    path = tmp_path / "old.json"
    write_snapshot(snapshot, path)
    required = [issue for issue in evaluate_snapshot(read_snapshot(path)).coverage[0]["issues"]
                if issue["operation"] == "RequiredFact"]
    assert required[0]["message"] == f"{check_id} requires {fact}; the fact is absent from this snapshot."


def test_missing_only_and_selection_exclusions(context):
    snapshot = capture_snapshot(context, ["secretsmanager"])
    snapshot.services["secretsmanager"].resources[0].data.clear()
    coverage = evaluate_snapshot(snapshot).coverage[0]
    assert coverage["status"] == "NOT_SCANNED"
    assert coverage["evaluated"] == 0 and coverage["not_scanned"] == 3
    assert sum(issue["operation"] == "RequiredFact" for issue in coverage["issues"]) == 3
    selected = evaluate_snapshot(snapshot, selected_checks=["AWSH-SECRET-001"])
    assert sum(issue["operation"] == "RequiredFact" for issue in selected.coverage[0]["issues"]) == 1
    excluded = evaluate_snapshot(snapshot, selected_resources=["different-secret"])
    assert not any(issue["operation"] == "RequiredFact" for issue in excluded.coverage[0]["issues"])
    assert excluded.coverage[0]["not_scanned"] == 3


def test_complete_secret_keeps_existing_secure_and_insecure_behavior(context):
    snapshot = capture_snapshot(context, ["secretsmanager"])
    secure = evaluate_snapshot(snapshot)
    assert secure.coverage[0]["status"] == "COMPLETE"
    assert secure.coverage[0]["evaluated"] == 3
    assert not secure.findings
    resource = snapshot.services["secretsmanager"].resources[0]
    resource.data["rotation"] = False
    insecure = evaluate_snapshot(snapshot)
    assert [finding.id for finding in insecure.findings] == ["AWSH-SECRET-001"]
    assert insecure.coverage[0]["status"] == "COMPLETE"
    assert not any(issue["operation"] == "RequiredFact" for issue in insecure.coverage[0]["issues"])


@pytest.mark.parametrize("fact,operation,check_id", FACT_OPERATIONS)
def test_actual_collector_failure_maps_to_required_fact(context, fact, operation, check_id):
    client = context.session.client("secretsmanager")
    secret = client.get_paginator.return_value.paginate.return_value[0]["SecretList"][0]
    if fact == "rotation":
        secret["RotationEnabled"] = "invalid"
    elif fact == "policy":
        client.get_resource_policy.side_effect = aws_error("AccessDenied")
    else:
        secret["KmsKeyId"] = "key-id"
        context.session.client("kms").describe_key.side_effect = aws_error("AccessDenied")
    snapshot = capture_snapshot(context, ["secretsmanager"])
    assert any(issue.operation == operation and issue.resource_id == "test-secret"
               for issue in snapshot.services["secretsmanager"].issues)
    coverage = evaluate_snapshot(snapshot).coverage[0]
    assert any(issue["operation"] == "RequiredFact" and
               issue["message"] == f"{check_id} requires {fact}; a related collection issue is recorded separately."
               for issue in coverage["issues"])
    assert coverage["status"] == "PARTIAL" and coverage["not_scanned"] == 1


def test_denied_collector_fact_replays_in_all_reporters(context, monkeypatch, tmp_path):
    context.session.client("secretsmanager").get_resource_policy.side_effect = aws_error("AccessDenied")
    snapshot = capture_snapshot(context, ["secretsmanager"])
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    assert snapshot.services["secretsmanager"].issues[0].operation == "GetResourcePolicy"
    factory = Mock(side_effect=AssertionError("offline replay must not authenticate"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(path), "--output", "json"])
    assert result.exit_code == 1
    issues = json.loads(result.stdout)["coverage"][0]["issues"]
    assert any(issue["operation"] == "RequiredFact" and
               issue["message"] == "AWSH-SECRET-002 requires policy; a related collection issue is recorded separately."
               for issue in issues)
    console = runner.invoke(app, ["scan", str(path), "--no-progress"])
    assert console.exit_code == 1 and "AWSH-SECRET-002 requires policy" in console.output
    html = tmp_path / "report.html"
    result = runner.invoke(app, ["scan", str(path), "--output", "html", "--report-file", str(html)])
    assert result.exit_code == 1 and "AWSH-SECRET-002 requires policy" in html.read_text()
    factory.assert_not_called()
