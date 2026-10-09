"""KMS missing-fact explanations remain key-specific and offline-safe."""

import json
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.collectors.common import CollectionIssue
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.snapshot import capture_snapshot, read_snapshot, write_snapshot
from test_audit import context
from test_s3 import aws_error


FACT_OPERATIONS = (
    ("rotation", "GetKeyRotationStatus", "AWSH-KMS-001"),
    ("policy", "GetKeyPolicy", "AWSH-KMS-002"),
)


def one_key(context):
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = [
        {"Keys": [{"KeyId": "key-1"}]}
    ]
    return capture_snapshot(context, ["kms"])


@pytest.mark.parametrize("fact,operation,check_id", FACT_OPERATIONS)
def test_related_issue_names_only_key_check_and_fact(context, fact, operation, check_id):
    snapshot = one_key(context)
    snapshot.services["kms"].resources[0].data.pop(fact)
    snapshot.services["kms"].issues.append(CollectionIssue("key-1", operation, "AccessDenied: private-marker"))
    coverage = evaluate_snapshot(snapshot).coverage[0]
    required = [issue for issue in coverage["issues"] if issue["operation"] == "RequiredFact"]
    assert required == [{"resource_id": "key-1", "operation": "RequiredFact",
                         "message": f"{check_id} requires {fact}; a related collection issue is recorded separately."}]
    assert "private-marker" not in required[0]["message"]
    assert coverage["status"] == "PARTIAL"
    assert coverage["evaluated"] == 1 and coverage["not_scanned"] == 1


@pytest.mark.parametrize("fact,operation,check_id", FACT_OPERATIONS)
def test_unrelated_issue_does_not_claim_related_failure(context, tmp_path, fact, operation, check_id):
    snapshot = one_key(context)
    snapshot.services["kms"].resources[0].data.pop(fact)
    snapshot.services["kms"].issues.extend([
        CollectionIssue("other-key", operation, "AccessDenied"),
        CollectionIssue("key-1", "OtherRead", "AccessDenied"),
    ])
    path = tmp_path / "old.json"
    write_snapshot(snapshot, path)
    required = [issue for issue in evaluate_snapshot(read_snapshot(path)).coverage[0]["issues"]
                if issue["operation"] == "RequiredFact"]
    assert required[0]["message"] == f"{check_id} requires {fact}; the fact is absent from this snapshot."


@pytest.mark.parametrize("fact,operation,check_id", FACT_OPERATIONS)
def test_actual_collector_denial_maps_to_fact(context, fact, operation, check_id):
    one_key(context)
    client = context.session.client.return_value
    if fact == "rotation":
        client.get_key_rotation_status.side_effect = aws_error("AccessDenied")
    else:
        client.get_key_policy.side_effect = aws_error("AccessDenied")
    snapshot = capture_snapshot(context, ["kms"])
    assert any(issue.operation == operation and issue.resource_id == "key-1"
               for issue in snapshot.services["kms"].issues)
    coverage = evaluate_snapshot(snapshot).coverage[0]
    assert any(issue["operation"] == "RequiredFact" and
               issue["message"] == f"{check_id} requires {fact}; a related collection issue is recorded separately."
               for issue in coverage["issues"])
    assert coverage["status"] == "PARTIAL" and coverage["not_scanned"] == 1


def test_missing_only_and_selection_exclusions(context):
    snapshot = one_key(context)
    snapshot.services["kms"].resources[0].data.clear()
    coverage = evaluate_snapshot(snapshot).coverage[0]
    assert coverage["status"] == "NOT_SCANNED"
    assert coverage["evaluated"] == 0 and coverage["not_scanned"] == 2
    assert sum(issue["operation"] == "RequiredFact" for issue in coverage["issues"]) == 2
    selected = evaluate_snapshot(snapshot, selected_checks=["AWSH-KMS-001"])
    assert sum(issue["operation"] == "RequiredFact" for issue in selected.coverage[0]["issues"]) == 1
    excluded = evaluate_snapshot(snapshot, selected_resources=["other-key"])
    assert not any(issue["operation"] == "RequiredFact" for issue in excluded.coverage[0]["issues"])
    assert excluded.coverage[0]["not_scanned"] == 2


def test_complete_key_retains_secure_and_insecure_results(context):
    snapshot = one_key(context)
    secure = evaluate_snapshot(snapshot)
    assert secure.coverage[0]["status"] == "COMPLETE"
    assert secure.coverage[0]["evaluated"] == 2 and not secure.findings
    resource = snapshot.services["kms"].resources[0]
    resource.data["rotation"]["enabled"] = False
    insecure = evaluate_snapshot(snapshot)
    assert [finding.id for finding in insecure.findings] == ["AWSH-KMS-001"]
    assert insecure.coverage[0]["status"] == "COMPLETE"
    assert not any(issue["operation"] == "RequiredFact" for issue in insecure.coverage[0]["issues"])


@pytest.mark.parametrize("field,value", [("KeyManager", "AWS"), ("KeySpec", "RSA_2048")])
def test_aws_managed_and_ineligible_keys_do_not_gain_false_missing_facts(context, field, value):
    client = context.session.client.return_value
    client.describe_key.return_value["KeyMetadata"][field] = value
    snapshot = one_key(context)
    coverage = evaluate_snapshot(snapshot).coverage[0]
    assert coverage["status"] == "COMPLETE"
    assert coverage["evaluated"] == (1 if field == "KeyManager" else 2)
    assert not any(issue["operation"] == "RequiredFact" for issue in coverage["issues"])


def test_describe_denial_before_resource_has_no_per_key_required_fact(context):
    client = context.session.client.return_value
    client.describe_key.side_effect = aws_error("AccessDenied")
    snapshot = one_key(context)
    coverage = evaluate_snapshot(snapshot).coverage[0]
    assert coverage["resources"] == 0
    assert coverage["status"] == "ACCESS_DENIED"
    assert not any(issue["operation"] == "RequiredFact" for issue in coverage["issues"])


def test_offline_json_console_html_explain_without_authenticating(context, monkeypatch, tmp_path):
    snapshot = one_key(context)
    snapshot.services["kms"].resources[0].data.pop("policy")
    snapshot.services["kms"].issues.append(CollectionIssue("key-1", "GetKeyPolicy", "AccessDenied"))
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    factory = Mock(side_effect=AssertionError("offline replay must not authenticate"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(path), "--output", "json"])
    assert result.exit_code == 1
    issues = json.loads(result.stdout)["coverage"][0]["issues"]
    assert any(issue["operation"] == "RequiredFact" and
               issue["message"] == "AWSH-KMS-002 requires policy; a related collection issue is recorded separately."
               for issue in issues)
    assert "private-marker" not in result.stdout
    console = runner.invoke(app, ["scan", str(path), "--no-progress"])
    assert console.exit_code == 1 and "AWSH-KMS-002 requires policy" in console.output
    html = tmp_path / "report.html"
    result = runner.invoke(app, ["scan", str(path), "--output", "html", "--report-file", str(html)])
    assert result.exit_code == 1 and "AWSH-KMS-002 requires policy" in html.read_text()
    factory.assert_not_called()
