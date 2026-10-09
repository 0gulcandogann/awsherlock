"""Lambda missing-fact explanations preserve coverage and offline safety."""

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
    ("urls", "ListFunctionUrlConfigs", "AWSH-LAMBDA-001"),
    ("role_policies", "ListAttachedRolePolicies", "AWSH-LAMBDA-002"),
    ("runtime", "ManagedRuntime (images/unknown runtimes not scanned)", "AWSH-LAMBDA-003"),
)


@pytest.mark.parametrize("fact,operation,check_id", FACT_OPERATIONS)
def test_matching_function_issue_names_only_check_and_fact(context, fact, operation, check_id):
    snapshot = capture_snapshot(context, ["lambda"])
    snapshot.services["lambda"].resources[0].data.pop(fact)
    snapshot.services["lambda"].issues.append(CollectionIssue("test", operation, "AccessDenied: private-marker"))
    coverage = evaluate_snapshot(snapshot).coverage[0]
    required = [issue for issue in coverage["issues"] if issue["operation"] == "RequiredFact"]
    assert required == [{"resource_id": "test", "operation": "RequiredFact",
                         "message": f"{check_id} requires {fact}; a related collection issue is recorded separately."}]
    assert "private-marker" not in required[0]["message"]
    assert coverage["status"] == "PARTIAL"
    assert coverage["evaluated"] == 2 and coverage["not_scanned"] == 1


@pytest.mark.parametrize("fact,operation,check_id", FACT_OPERATIONS)
def test_old_snapshot_does_not_blame_unrelated_issue(context, tmp_path, fact, operation, check_id):
    snapshot = capture_snapshot(context, ["lambda"])
    snapshot.services["lambda"].resources[0].data.pop(fact)
    snapshot.services["lambda"].issues.extend([
        CollectionIssue("different-function", operation, "AccessDenied"),
        CollectionIssue("test", "OtherRead", "AccessDenied"),
    ])
    path = tmp_path / "old.json"
    write_snapshot(snapshot, path)
    required = [issue for issue in evaluate_snapshot(read_snapshot(path)).coverage[0]["issues"]
                if issue["operation"] == "RequiredFact"]
    assert required[0]["message"] == f"{check_id} requires {fact}; the fact is absent from this snapshot."


def test_missing_only_and_selection_exclusions(context):
    snapshot = capture_snapshot(context, ["lambda"])
    snapshot.services["lambda"].resources[0].data.clear()
    coverage = evaluate_snapshot(snapshot).coverage[0]
    assert coverage["status"] == "NOT_SCANNED"
    assert coverage["evaluated"] == 0 and coverage["not_scanned"] == 3
    assert sum(issue["operation"] == "RequiredFact" for issue in coverage["issues"]) == 3
    selected = evaluate_snapshot(snapshot, selected_checks=["AWSH-LAMBDA-001"])
    assert sum(issue["operation"] == "RequiredFact" for issue in selected.coverage[0]["issues"]) == 1
    excluded = evaluate_snapshot(snapshot, selected_resources=["different-function"])
    assert not any(issue["operation"] == "RequiredFact" for issue in excluded.coverage[0]["issues"])
    assert excluded.coverage[0]["not_scanned"] == 3


def test_complete_function_preserves_secure_and_insecure_results(context):
    snapshot = capture_snapshot(context, ["lambda"])
    resource = snapshot.services["lambda"].resources[0]
    resource.data["urls"] = []
    resource.data["role_policies"] = []
    resource.data["runtime"]["deprecated"] = False
    secure = evaluate_snapshot(snapshot)
    assert secure.coverage[0]["status"] == "COMPLETE"
    assert secure.coverage[0]["evaluated"] == 3 and not secure.findings
    resource.data["urls"] = [{"arn": resource.resource_arn, "auth": "NONE"}]
    insecure = evaluate_snapshot(snapshot)
    assert [finding.id for finding in insecure.findings] == ["AWSH-LAMBDA-001"]
    assert insecure.coverage[0]["status"] == "COMPLETE"
    assert not any(issue["operation"] == "RequiredFact" for issue in insecure.coverage[0]["issues"])


@pytest.mark.parametrize("fact,operation,check_id", FACT_OPERATIONS)
def test_actual_collector_issue_maps_to_required_fact(context, fact, operation, check_id):
    client = context.session.client("lambda")
    if fact == "urls":
        original = client.get_paginator.side_effect

        def paginator(method):
            if method == "list_function_url_configs":
                raise aws_error("AccessDenied")
            return original(method)

        client.get_paginator.side_effect = paginator
    elif fact == "role_policies":
        context.session.client("iam").get_paginator.side_effect = aws_error("AccessDenied")
    else:
        client.get_paginator("list_functions").paginate.return_value[0]["Functions"][0]["PackageType"] = "Image"
    snapshot = capture_snapshot(context, ["lambda"])
    assert any(issue.operation == operation and issue.resource_id == "test"
               for issue in snapshot.services["lambda"].issues)
    coverage = evaluate_snapshot(snapshot).coverage[0]
    assert any(issue["operation"] == "RequiredFact" and
               issue["message"] == f"{check_id} requires {fact}; a related collection issue is recorded separately."
               for issue in coverage["issues"])
    assert coverage["status"] == "PARTIAL" and coverage["not_scanned"] == 1


def test_offline_json_console_html_explain_without_authenticating(context, monkeypatch, tmp_path):
    snapshot = capture_snapshot(context, ["lambda"])
    snapshot.services["lambda"].resources[0].data.pop("role_policies")
    snapshot.services["lambda"].issues.append(CollectionIssue("test", "ListAttachedRolePolicies", "AccessDenied"))
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    factory = Mock(side_effect=AssertionError("offline replay must not authenticate"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(path), "--output", "json"])
    assert result.exit_code == 1
    issues = json.loads(result.stdout)["coverage"][0]["issues"]
    assert any(issue["operation"] == "RequiredFact" and
               issue["message"] == "AWSH-LAMBDA-002 requires role_policies; a related collection issue is recorded separately."
               for issue in issues)
    assert "secret-marker" not in result.stdout
    console = runner.invoke(app, ["scan", str(path), "--no-progress"])
    assert console.exit_code == 1 and "AWSH-LAMBDA-002 requires role_policies" in console.output
    assert "secret-marker" not in console.output
    html = tmp_path / "report.html"
    result = runner.invoke(app, ["scan", str(path), "--output", "html", "--report-file", str(html)])
    assert result.exit_code == 1 and "AWSH-LAMBDA-002 requires role_policies" in html.read_text()
    assert "secret-marker" not in result.output + html.read_text()
    factory.assert_not_called()
