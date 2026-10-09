from dataclasses import replace
import json
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.organization import scan_organization
from awsherlock.reporting import render_html
from awsherlock.selection import parse_account_selection, parse_check_selection
from awsherlock.snapshot import write_snapshot
from test_s3 import context
from test_snapshot import snapshot
from test_organization import account


def test_selector_normalization():
    assert parse_check_selection(" awsh-ct-001,AWSH-CT-001 ") == ["AWSH-CT-001"]
    assert parse_account_selection("123456789012, 123456789012") == ["123456789012"]
    assert parse_check_selection(None) is None
    assert parse_account_selection(None) is None


@pytest.mark.parametrize("flag,value", [("--checks", ""), ("--checks", "AWSH-CT-999"),
                                      ("--checks", "AWSH-CT-001,"), ("--checks", "secret-marker"),
                                      ("--accounts", ""), ("--accounts", "123"),
                                      ("--accounts", "123456789012,"), ("--accounts", "secret-marker")])
def test_invalid_selectors_fail_before_auth(monkeypatch, flag, value):
    factory = Mock(side_effect=AssertionError("No AWS"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    result = CliRunner().invoke(app, ["scan", "organization", flag, value, "--no-progress"])
    assert result.exit_code == 2 and "secret-marker" not in result.output
    factory.assert_not_called()


def test_check_selection_keeps_resources_and_exclusions(snapshot):
    snapshot.services["s3"].resources[0].data.update(encryption=["AES256"], versioning="Enabled", policy_public=None)
    before = evaluate_snapshot(snapshot)
    report = evaluate_snapshot(snapshot, ["AWSH-S3-001"])
    assert all(finding.id == "AWSH-S3-001" for finding in report.findings)
    assert report.incomplete and report.coverage[0]["status"] == "PARTIAL"
    assert report.to_dict()["summary"]["resources"] == before.to_dict()["summary"]["resources"]
    assert report.to_dict()["summary"]["checks_evaluated"] < before.to_dict()["summary"]["checks_evaluated"]
    assert any(issue["operation"] == "CheckSelection" for issue in report.coverage[0]["issues"])
    assert "Checks excluded by selection" in render_html(report)


def test_all_checks_selected_keeps_original_coverage(snapshot):
    from awsherlock.catalog import check_catalog
    identifiers = [identifier for identifier, service, _ in check_catalog() if service in snapshot.services]
    assert evaluate_snapshot(snapshot, identifiers).coverage == evaluate_snapshot(snapshot).coverage


def test_unselected_empty_service_is_not_scanned(snapshot):
    from awsherlock.collectors.common import CollectionResult
    snapshot.services["kms"] = CollectionResult()
    report = evaluate_snapshot(snapshot, ["AWSH-S3-001"])
    assert report.coverage[1]["status"] == "NOT_SCANNED"
    assert report.coverage[1]["resources"] == 0


def test_selection_does_not_hide_rule_evaluation_error(snapshot, monkeypatch):
    snapshot.services["s3"].issues.clear()
    monkeypatch.setattr("awsherlock.evaluation.evaluate_rules", Mock(side_effect=ValueError("invalid")))
    report = evaluate_snapshot(snapshot, ["AWSH-S3-001"])
    assert report.coverage[0]["status"] == "ERROR"
    assert any(issue["operation"] == "RuleEvaluation" for issue in report.coverage[0]["issues"])


def test_offline_selection_and_absent_check(snapshot, tmp_path, monkeypatch):
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    factory = Mock(side_effect=AssertionError("Offline"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    selected = CliRunner().invoke(app, ["scan", str(path), "--checks", "AWSH-S3-001", "--output", "json"])
    assert selected.exit_code == 1
    assert json.loads(selected.stdout)["metadata"]["selected_checks"] == ["AWSH-S3-001"]
    absent = CliRunner().invoke(app, ["scan", str(path), "--checks", "AWSH-CT-001"])
    assert absent.exit_code == 1 and "absent from the snapshot" in absent.output
    factory.assert_not_called()


def test_incompatible_service_or_account_scope_fails_before_auth(monkeypatch):
    factory = Mock(side_effect=AssertionError("No AWS"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    for args in [["scan", "--accounts", "123456789012"],
                 ["scan", "--services", "s3", "--checks", "AWSH-CT-001"]]:
        assert CliRunner().invoke(app, args).exit_code == 2
    factory.assert_not_called()


@pytest.mark.parametrize("regions", [None, ["eu-west-1", "eu-central-1"]])
def test_unselected_accounts_never_assumed_and_unknown_requested_account_visible(context, monkeypatch, regions):
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = [
        {"Accounts": [account(1), account(2)]}]
    factory = Mock(side_effect=AssertionError("Unselected accounts must not be assumed"))
    monkeypatch.setattr("awsherlock.organization.create_scan_context", factory)
    report = scan_organization(context, ["kms"], selected_accounts=["000000000003"], regions=regions)
    assert report.incomplete
    assert {entry["account_id"] for entry in report.coverage} == {"000000000001", "000000000002", "000000000003"}
    assert all(entry["status"] == "NOT_SCANNED" for entry in report.coverage)
    assert all(entry["operation"] == "AccountSelection" for row in report.coverage for entry in row["issues"])
    factory.assert_not_called()


def test_selected_member_scanned_and_others_excluded(context, snapshot, monkeypatch):
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = [{"Accounts": [account(1), account(2)]}]
    factory = Mock(return_value=replace(context, account_id="000000000001"))
    monkeypatch.setattr("awsherlock.organization.create_scan_context", factory)
    monkeypatch.setattr("awsherlock.organization.capture_snapshot", lambda target, services:
                        replace(snapshot, metadata=replace(snapshot.metadata, account_id=target.account_id),
                                services={"s3": type(snapshot.services["s3"])([], [])}))
    report = scan_organization(context, ["s3"], selected_accounts=["000000000001"])
    assert factory.call_count == 1
    assert [row["status"] for row in report.coverage] == ["COMPLETE", "NOT_SCANNED"]
    assert report.metadata["selected_accounts"] == ["000000000001"]
