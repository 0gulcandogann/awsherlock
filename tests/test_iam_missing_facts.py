"""Core IAM missing-fact coverage is check-specific and hides key identifiers."""

import json
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.collectors.common import CollectionIssue
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.snapshot import capture_snapshot, read_snapshot, write_snapshot
from test_iam import context
from test_s3 import aws_error


FACT_CASES = (
    ("alice", "attached", "PolicyNormalization", ("AWSH-IAM-001",)),
    ("alice", "statements", "PolicyNormalization", ("AWSH-IAM-002", "AWSH-IAM-003")),
    ("alice", "console_mfa", "ConsoleMFA", ("AWSH-IAM-004",)),
    ("alice/key-1", "key_age", "ListAccessKeys", ("AWSH-IAM-005",)),
    ("alice/key-1", "key_stale", "GetAccessKeyLastUsed", ("AWSH-IAM-006",)),
)


def required(report):
    return [issue for issue in report.coverage[0]["issues"] if issue["operation"] == "RequiredFact"]


def resource(snapshot, name):
    return next(item for item in snapshot.services["iam"].resources if item.resource_id == name)


@pytest.mark.parametrize("name,fact,operation,check_ids", FACT_CASES)
def test_missing_fact_names_check_and_matching_safe_issue(context, name, fact, operation, check_ids):
    snapshot = capture_snapshot(context, ["iam"])
    resource(snapshot, name).data.pop(fact)
    snapshot.services["iam"].issues.append(CollectionIssue(name, operation, "AccessDenied: private-marker"))
    report = evaluate_snapshot(snapshot)
    messages = [issue["message"] for issue in required(report)]
    reason = ("a related collection issue is recorded separately" if fact != "key_age" else
              "the fact is absent from this snapshot")
    assert messages == [f"{check_id} requires {fact}; {reason}." for check_id in check_ids]
    assert all(issue["resource_id"] == name for issue in required(report))
    assert "private-marker" not in " ".join(messages)
    assert "synthetic-key-marker" not in json.dumps(report.to_dict())
    assert report.coverage[0]["status"] == "PARTIAL"


@pytest.mark.parametrize("name,fact,operation,check_ids", FACT_CASES)
def test_old_snapshot_does_not_blame_unrelated_resource(context, tmp_path, name, fact, operation, check_ids):
    snapshot = capture_snapshot(context, ["iam"])
    resource(snapshot, name).data.pop(fact)
    snapshot.services["iam"].issues.append(CollectionIssue("different-resource", operation, "AccessDenied"))
    path = tmp_path / "old.json"
    write_snapshot(snapshot, path)
    assert [issue["message"] for issue in required(evaluate_snapshot(read_snapshot(path)))] == [
        f"{check_id} requires {fact}; the fact is absent from this snapshot." for check_id in check_ids
    ]


def test_actual_denied_reads_map_to_console_and_key_checks(context):
    client = context.session.client.return_value
    client.get_login_profile.side_effect = aws_error("AccessDenied")
    client.get_access_key_last_used.side_effect = aws_error("AccessDenied")
    report = evaluate_snapshot(capture_snapshot(context, ["iam"]))
    messages = [issue["message"] for issue in required(report)]
    assert messages == [
        "AWSH-IAM-004 requires console_mfa; a related collection issue is recorded separately.",
        "AWSH-IAM-006 requires key_stale; a related collection issue is recorded separately.",
    ]
    assert report.coverage[0]["status"] == "PARTIAL"


def test_policy_resource_and_inactive_key_exceptions(context):
    snapshot = capture_snapshot(context, ["iam"])
    resource(snapshot, "managed").data.pop("statements")
    resource(snapshot, "alice/key-1").data["key_age"]["active"] = False
    resource(snapshot, "alice/key-1").data.pop("key_stale")
    snapshot.services["iam"].issues.append(CollectionIssue("managed", "PolicyNormalization", "Invalid AWS response"))
    report = evaluate_snapshot(snapshot)
    assert [issue["message"] for issue in required(report)] == [
        "AWSH-IAM-002 requires statements; a related collection issue is recorded separately.",
        "AWSH-IAM-003 requires statements; a related collection issue is recorded separately.",
    ]
    assert report.coverage[0]["not_scanned"] == 2


def test_selection_and_missing_only_keep_coverage_incomplete(context):
    snapshot = capture_snapshot(context, ["iam"])
    resource(snapshot, "alice").data.clear()
    report = evaluate_snapshot(snapshot)
    assert len(required(report)) == 4
    assert report.coverage[0]["not_scanned"] == 4
    selected = evaluate_snapshot(snapshot, selected_checks=["AWSH-IAM-005"])
    assert not required(selected)
    excluded = evaluate_snapshot(snapshot, selected_resources=["managed"])
    assert not required(excluded)


def test_secure_and_insecure_results_unchanged(context):
    snapshot = capture_snapshot(context, ["iam"])
    secure = evaluate_snapshot(snapshot)
    assert secure.coverage[0]["status"] == "COMPLETE"
    assert not required(secure)
    resource(snapshot, "alice").data["attached"] = ["arn:aws:iam::aws:policy/AdministratorAccess"]
    insecure = evaluate_snapshot(snapshot)
    assert any(finding.id == "AWSH-IAM-001" for finding in insecure.findings)
    assert insecure.coverage[0]["status"] == "COMPLETE"
    assert not required(insecure)


def test_offline_json_console_html_explain_without_authenticating(context, monkeypatch, tmp_path):
    client = context.session.client.return_value
    client.get_access_key_last_used.side_effect = aws_error("AccessDenied")
    snapshot = capture_snapshot(context, ["iam"])
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    factory = Mock(side_effect=AssertionError("offline replay must not authenticate"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(path), "--output", "json"])
    assert result.exit_code == 1
    issues = json.loads(result.stdout)["coverage"][0]["issues"]
    assert any(issue["operation"] == "RequiredFact" and
               issue["message"] == "AWSH-IAM-006 requires key_stale; a related collection issue is recorded separately."
               for issue in issues)
    assert "synthetic-key-marker" not in result.stdout
    console = runner.invoke(app, ["scan", str(path), "--no-progress"])
    assert console.exit_code == 1 and "AWSH-IAM-006 requires key_stale" in console.output
    html = tmp_path / "report.html"
    result = runner.invoke(app, ["scan", str(path), "--output", "html", "--report-file", str(html)])
    assert result.exit_code == 1 and "AWSH-IAM-006 requires key_stale" in html.read_text()
    assert "synthetic-key-marker" not in html.read_text()
    factory.assert_not_called()
