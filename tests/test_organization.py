from dataclasses import replace
from unittest.mock import Mock
import json

import pytest
from botocore.exceptions import ClientError
from typer.testing import CliRunner

from awsherlock.aws.session import SessionError
from awsherlock.cli import app
from awsherlock.organization import scan_organization
from awsherlock.reporting import render_html, render_json, render_console
from test_s3 import context
from test_snapshot import snapshot


def account(number, state="ACTIVE"):
    return {"Id": f"{number:012}", "Name": f"Example {number}", "State": state}


def test_multiple_accounts_and_failures(context, snapshot, monkeypatch, capsys):
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = [
        {"Accounts": []}, {"Accounts": [account(1), account(2)]},
        {"Accounts": [account(3), account(4, "SUSPENDED"), account(1)]}]
    factory = Mock(side_effect=[replace(context, account_id="000000000001"),
                                SessionError("AccessDenied: AWS AssumeRole request was denied."),
                                replace(context, account_id="000000000003")])
    monkeypatch.setattr("awsherlock.organization.create_scan_context", factory)
    def capture(target, services):
        return replace(snapshot, metadata=replace(snapshot.metadata, account_id=target.account_id),
                       services={"s3": type(snapshot.services["s3"])([], [])})
    monkeypatch.setattr("awsherlock.organization.capture_snapshot", capture)
    report = scan_organization(context, ["s3"], "audit/Reader", "external-test", "scan-test")
    assert len(report.metadata["accounts"]) == 4
    assert [entry["status"] for entry in report.coverage] == ["COMPLETE", "ACCESS_DENIED", "COMPLETE", "NOT_SCANNED"]
    assert report.incomplete
    assert factory.call_count == 3
    assert factory.call_args_list[0].kwargs == {"source_session": context.session,
        "role": "arn:aws:iam::000000000001:role/audit/Reader", "external_id": "external-test", "role_session_name": "scan-test"}
    assert "AccessDenied" in render_json(report)
    assert "SUSPENDED" in render_html(report)
    render_console(report)
    assert "000000000002" in capsys.readouterr().err


def test_discovery_failure_preserves_discovered_accounts(context, monkeypatch):
    def pages():
        yield {"Accounts": [account(1, "CLOSED")]}
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "secret-marker"}}, "ListAccounts")
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = pages()
    report = scan_organization(context, ["s3"])
    assert report.incomplete
    assert len(report.metadata["accounts"]) == 1
    assert "secret-marker" not in render_json(report)
    assert report.coverage[0]["issues"][0]["message"] == "AccessDenied"


@pytest.mark.parametrize("raw", [{"Id": "bad"}, {"Id": "000000000001", "Name": "Example", "Status": "ACTIVE"}])
def test_malformed_account_is_visible(context, raw):
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = [{"Accounts": [raw]}]
    assert scan_organization(context, ["s3"]).incomplete


def test_organization_cli(context, monkeypatch):
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = [{"Accounts": []}]
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    result = CliRunner().invoke(app, ["scan", "organization", "--profile", "audit", "--output", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["metadata"]["accounts"] == []
    assert CliRunner().invoke(app, ["scan", "--role-name", "Reader"]).exit_code == 2
    assert CliRunner().invoke(app, ["scan", "organization", "--role-name", "bad name"]).exit_code == 1
