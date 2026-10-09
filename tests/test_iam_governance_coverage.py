"""Opt-in IAM governance keeps unknown joins and missing evidence incomplete."""

import json
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.collectors.common import CollectionIssue
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.snapshot import read_snapshot, write_snapshot
from test_identity import ROLE, USER, identity_context, snapshot_at
from test_s3 import aws_error


def required(report):
    return [issue for issue in report.coverage[0]["issues"] if issue["operation"] == "RequiredFact"]


def role_resource(snapshot):
    return next(resource for resource in snapshot.services["iam"].resources if resource.resource_arn == ROLE)


@pytest.mark.parametrize("fact,operation,check_ids", [
    ("identity_profile", "IdentityProfile", ("AWSH-IAM-007", "AWSH-IAM-008")),
    ("identity_usage", "RoleLastUsed", ("AWSH-IAM-009",)),
    ("identity_trust", "RoleTrust", ("AWSH-IAM-010",)),
    ("identity_approval", "OtherRead", ("AWSH-IAM-011", "AWSH-IAM-012")),
])
def test_missing_governance_fact_names_check_and_safe_reason(identity_context, fact, operation, check_ids):
    snapshot = snapshot_at(identity_context[0])
    role_resource(snapshot).data.pop(fact)
    snapshot.services["iam"].issues.append(CollectionIssue("worker", operation, "AccessDenied: private-marker"))
    report = evaluate_snapshot(snapshot)
    messages = [issue["message"] for issue in required(report)]
    reason = ("a related collection issue is recorded separately" if fact != "identity_approval" else
              "the fact is absent from this snapshot")
    assert messages == [f"{check_id} requires {fact}; {reason}." for check_id in check_ids]
    assert all(issue["resource_id"] == "worker" for issue in required(report))
    assert "private-marker" not in " ".join(messages)
    assert report.incomplete


def test_unrelated_issue_and_old_snapshot_do_not_claim_related_failure(identity_context, tmp_path):
    snapshot = snapshot_at(identity_context[0])
    role_resource(snapshot).data.pop("identity_profile")
    snapshot.services["iam"].issues.append(CollectionIssue("integration", "IdentityProfile", "AccessDenied"))
    path = tmp_path / "old.json"
    write_snapshot(snapshot, path)
    messages = [issue["message"] for issue in required(evaluate_snapshot(read_snapshot(path)))]
    assert messages == [
        "AWSH-IAM-007 requires identity_profile; the fact is absent from this snapshot.",
        "AWSH-IAM-008 requires identity_profile; the fact is absent from this snapshot.",
    ]


def test_denied_managed_policy_join_marks_no_finding_as_incomplete(identity_context):
    context, clients, role, user, pages = identity_context
    role["AttachedManagedPolicies"] = [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
    clients["iam"].get_policy.side_effect = aws_error("AccessDenied")
    report = evaluate_snapshot(snapshot_at(context))
    messages = [issue["message"] for issue in required(report)]
    assert messages == [
        "AWSH-IAM-002 requires complete identity_policy_context; a related collection issue is recorded separately.",
        "AWSH-IAM-003 requires complete identity_policy_context; a related collection issue is recorded separately.",
    ]
    assert report.coverage[0]["not_scanned"] == 2
    assert any(finding.id == "AWSH-IAM-001" for finding in report.findings)
    assert not any(finding.id in {"AWSH-IAM-002", "AWSH-IAM-003"} for finding in report.findings)


def test_known_policy_findings_survive_incomplete_join(identity_context):
    context, clients, role, user, pages = identity_context
    role["RolePolicyList"] = [{"PolicyDocument": {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}}]
    role["AttachedManagedPolicies"] = [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
    clients["iam"].get_policy.side_effect = aws_error("AccessDenied")
    report = evaluate_snapshot(snapshot_at(context))
    assert {finding.id for finding in report.findings if finding.resource_arn == ROLE} >= {
        "AWSH-IAM-001", "AWSH-IAM-002", "AWSH-IAM-003"
    }
    assert report.coverage[0]["not_scanned"] == 2
    assert len(required(report)) == 2


def test_old_context_and_selection_stay_conservative(identity_context, tmp_path):
    snapshot = snapshot_at(identity_context[0])
    role_resource(snapshot).data.pop("identity_policy_context")
    path = tmp_path / "old.json"
    write_snapshot(snapshot, path)
    report = evaluate_snapshot(read_snapshot(path))
    assert [issue["message"] for issue in required(report)] == [
        "AWSH-IAM-002 requires complete identity_policy_context; the fact is absent or incomplete in this snapshot.",
        "AWSH-IAM-003 requires complete identity_policy_context; the fact is absent or incomplete in this snapshot.",
    ]
    by_check = evaluate_snapshot(read_snapshot(path), selected_checks=["AWSH-IAM-001"])
    assert not required(by_check)
    by_resource = evaluate_snapshot(read_snapshot(path), selected_resources=[USER])
    assert not required(by_resource)


def test_complete_governance_keeps_secure_result(identity_context):
    report = evaluate_snapshot(snapshot_at(identity_context[0]))
    assert not report.incomplete and not report.findings and not required(report)


def test_offline_json_console_html_keep_context_issue_safe(identity_context, monkeypatch, tmp_path):
    context, clients, role, user, pages = identity_context
    role["AttachedManagedPolicies"] = [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
    clients["iam"].get_policy.side_effect = aws_error("AccessDenied")
    snapshot = snapshot_at(context)
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    factory = Mock(side_effect=AssertionError("offline replay must not authenticate"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(path), "--output", "json"])
    assert result.exit_code == 1
    issues = json.loads(result.stdout)["coverage"][0]["issues"]
    assert any(issue["operation"] == "RequiredFact" and "AWSH-IAM-002 requires complete identity_policy_context"
               in issue["message"] for issue in issues)
    assert "private-marker" not in result.stdout
    console = runner.invoke(app, ["scan", str(path), "--no-progress"])
    assert console.exit_code == 1 and "AWSH-IAM-002 requires complete identity_policy_context" in console.output
    html = tmp_path / "report.html"
    result = runner.invoke(app, ["scan", str(path), "--output", "html", "--report-file", str(html)])
    assert result.exit_code == 1 and "AWSH-IAM-002 requires complete identity_policy_context" in html.read_text()
    factory.assert_not_called()
