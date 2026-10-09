"""S3 missing-fact explanations preserve collection and selection semantics."""

import json
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.collectors.common import CollectionIssue
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.snapshot import capture_snapshot, read_snapshot, write_snapshot
from test_s3 import context


FACT_OPERATIONS = (
    ("public_access_block", "GetPublicAccessBlock", "AWSH-S3-001"),
    ("encryption", "GetBucketEncryption", "AWSH-S3-002"),
    ("versioning", "GetBucketVersioning", "AWSH-S3-003"),
    ("logging", "GetBucketLogging", "AWSH-S3-004"),
    ("policy_public", "GetBucketPolicyStatus", "AWSH-S3-005"),
)


@pytest.mark.parametrize("fact,operation,check_id", FACT_OPERATIONS)
def test_denied_bucket_fact_names_check_and_safe_operation(context, fact, operation, check_id):
    snapshot = capture_snapshot(context, ["s3"])
    snapshot.services["s3"].resources[0].data.pop(fact)
    snapshot.services["s3"].issues.append(CollectionIssue("test-bucket", operation, "AccessDenied: private-marker"))
    report = evaluate_snapshot(snapshot)
    coverage = report.coverage[0]
    required = [issue for issue in coverage["issues"] if issue["operation"] == "RequiredFact"]
    assert len(required) == 1
    assert required[0]["resource_id"] == "test-bucket"
    assert required[0]["message"] == f"{check_id} requires {fact}; a related collection issue is recorded separately."
    assert "private-marker" not in required[0]["message"]
    assert coverage["status"] == "PARTIAL"
    assert coverage["evaluated"] == 4 and coverage["not_scanned"] == 1
    assert report.incomplete and not report.findings


@pytest.mark.parametrize("fact,operation,check_id", FACT_OPERATIONS)
def test_old_snapshot_absence_does_not_claim_unrelated_failure(context, tmp_path, fact, operation, check_id):
    snapshot = capture_snapshot(context, ["s3"])
    snapshot.services["s3"].resources[0].data.pop(fact)
    snapshot.services["s3"].issues.append(CollectionIssue("different-bucket", operation, "AccessDenied"))
    path = tmp_path / "old.json"
    write_snapshot(snapshot, path)
    report = evaluate_snapshot(read_snapshot(path))
    required = [issue for issue in report.coverage[0]["issues"] if issue["operation"] == "RequiredFact"]
    assert required[0]["message"] == f"{check_id} requires {fact}; the fact is absent from this snapshot."


@pytest.mark.parametrize("fact,_,check_id", FACT_OPERATIONS)
def test_confirmed_absence_is_evaluated_not_a_missing_fact(context, fact, _, check_id):
    snapshot = capture_snapshot(context, ["s3"])
    snapshot.services["s3"].resources[0].data[fact] = None if fact != "policy_public" else False
    report = evaluate_snapshot(snapshot)
    assert report.coverage[0]["status"] == "COMPLETE"
    assert report.coverage[0]["evaluated"] == 5
    assert not any(issue["operation"] == "RequiredFact" for issue in report.coverage[0]["issues"])
    assert any(finding.id == check_id for finding in report.findings) == (fact != "policy_public")


def test_missing_only_and_account_context_stay_distinct(context):
    snapshot = capture_snapshot(context, ["s3"])
    snapshot.services["s3"].resources[0].data.clear()
    report = evaluate_snapshot(snapshot)
    coverage = report.coverage[0]
    assert coverage["status"] == "NOT_SCANNED"
    assert coverage["evaluated"] == 0 and coverage["not_scanned"] == 5
    assert sum(issue["operation"] == "RequiredFact" for issue in coverage["issues"]) == 5
    assert sum(issue["operation"] == "AccountPublicAccessContext" for issue in coverage["issues"]) == 1


def test_selected_check_and_resource_exclusions_suppress_required_fact(context):
    snapshot = capture_snapshot(context, ["s3"])
    snapshot.services["s3"].resources[0].data.pop("public_access_block")
    selected = evaluate_snapshot(snapshot, selected_checks=["AWSH-S3-002"])
    assert not any(issue["operation"] == "RequiredFact" for issue in selected.coverage[0]["issues"])
    excluded = evaluate_snapshot(snapshot, selected_resources=["other-bucket"])
    assert not any(issue["operation"] == "RequiredFact" for issue in excluded.coverage[0]["issues"])
    assert excluded.coverage[0]["not_scanned"] == 5


def test_offline_json_console_and_html_show_safe_explanation(context, monkeypatch, tmp_path):
    snapshot = capture_snapshot(context, ["s3"])
    snapshot.services["s3"].resources[0].data.pop("logging")
    snapshot.services["s3"].issues.append(CollectionIssue("test-bucket", "GetBucketLogging", "AccessDenied"))
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    factory = Mock(side_effect=AssertionError("offline replay must not authenticate"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(path), "--output", "json"])
    assert result.exit_code == 1
    issues = json.loads(result.stdout)["coverage"][0]["issues"]
    assert any(issue["operation"] == "RequiredFact" and "AWSH-S3-004 requires logging" in issue["message"]
               for issue in issues)
    console = runner.invoke(app, ["scan", str(path), "--no-progress"])
    assert console.exit_code == 1 and "AWSH-S3-004 requires logging" in console.output
    html = tmp_path / "report.html"
    result = runner.invoke(app, ["scan", str(path), "--output", "html", "--report-file", str(html)])
    assert result.exit_code == 1 and "AWSH-S3-004 requires logging" in html.read_text()
    factory.assert_not_called()
