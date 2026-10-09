from dataclasses import replace
from unittest.mock import Mock

import boto3
import pytest
from botocore.stub import Stubber
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.organization import discover_ou_accounts, scan_organization
from awsherlock.selection import parse_ou_selection
from test_s3 import context, aws_error
from test_organization import account
from test_snapshot import snapshot

OU = "ou-abcd-12345678"
NESTED = "ou-abcd-87654321"


def setup_discovery(context, failure=False):
    client = context.session.client.return_value
    def paginator(operation):
        if operation == "list_accounts":
            return Mock(paginate=Mock(return_value=[{"Accounts": [account(1), account(2), account(3)]}]))
        def pages(**kwargs):
            if kwargs["ParentId"] == OU and kwargs["ChildType"] == "ACCOUNT":
                yield {"Children": [{"Id": "000000000001", "Type": "ACCOUNT"}]}
                yield {"Children": []}
            elif kwargs["ParentId"] == OU:
                yield {"Children": [{"Id": NESTED, "Type": "ORGANIZATIONAL_UNIT"}]}
            elif failure:
                raise aws_error("AccessDenied")
            elif kwargs["ChildType"] == "ACCOUNT":
                yield {"Children": [{"Id": "000000000002", "Type": "ACCOUNT"}]}
            else:
                yield {"Children": []}
        return Mock(paginate=pages)
    client.get_paginator.side_effect = paginator
    return client


@pytest.mark.parametrize("accounts,expected", [(None, 2), (["000000000002"], 1), (["000000000003"], 0)])
def test_ou_descendants_intersection_and_exclusion(context, snapshot, monkeypatch, accounts, expected):
    setup_discovery(context)
    factory = Mock(side_effect=lambda **kwargs: replace(context, account_id=kwargs["role"].split(":")[4]))
    monkeypatch.setattr("awsherlock.organization.create_scan_context", factory)
    monkeypatch.setattr("awsherlock.organization.capture_snapshot", lambda target, services:
                        replace(snapshot, metadata=replace(snapshot.metadata, account_id=target.account_id),
                                services={"s3": type(snapshot.services["s3"])([], [])}))
    report = scan_organization(context, ["s3"], selected_ous=[OU], selected_accounts=accounts)
    assert factory.call_count == expected
    assert report.metadata["selected_ous"] == [OU]
    assert report.incomplete
    assert report.metadata["accounts"][2]["scan_status"] == "NOT_SCANNED"


def test_failed_descendant_discovery_never_assumes_even_known_members(context, monkeypatch):
    setup_discovery(context, failure=True)
    factory = Mock(side_effect=AssertionError("Uncertain membership"))
    monkeypatch.setattr("awsherlock.organization.create_scan_context", factory)
    report = scan_organization(context, ["kms"], selected_ous=[OU])
    factory.assert_not_called()
    assert report.incomplete
    assert report.coverage[0]["status"] == "ACCESS_DENIED"
    assert "secret-marker" not in str(report.to_dict())
    assert all(a["scan_status"] == "NOT_SCANNED" for a in report.metadata["accounts"])


def test_sdk_pagination_empty_page_and_overlap():
    client = boto3.client("organizations", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
    with Stubber(client) as stub:
        stub.add_response("list_children", {"Children": [], "NextToken": "next"}, {"ParentId": OU, "ChildType": "ACCOUNT"})
        stub.add_response("list_children", {"Children": [{"Id": "000000000001", "Type": "ACCOUNT"}]},
                          {"ParentId": OU, "ChildType": "ACCOUNT", "NextToken": "next"})
        stub.add_response("list_children", {"Children": []}, {"ParentId": OU, "ChildType": "ORGANIZATIONAL_UNIT"})
        assert discover_ou_accounts(client, [OU, OU]) == {"000000000001"}
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("value", ["", "ou-bad", OU + ",", "secret-marker"])
def test_invalid_ou_fails_before_auth(monkeypatch, value):
    factory = Mock()
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    result = CliRunner().invoke(app, ["scan", "organization", "--ous", value])
    assert result.exit_code == 2
    assert "secret-marker" not in result.output
    factory.assert_not_called()


def test_ou_rejects_single_account_and_offline_before_auth(monkeypatch):
    factory = Mock()
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    for args in [["scan", "--ous", OU], ["scan", "facts.json", "--ous", OU]]:
        assert CliRunner().invoke(app, args).exit_code == 2
    factory.assert_not_called()
    assert parse_ou_selection(f" {OU},{OU}") == [OU]


@pytest.mark.parametrize("child", [{"Id": "bad", "Type": "ACCOUNT"}, {"Id": OU, "Type": "ACCOUNT"}, None])
def test_invalid_child_is_not_membership(context, child):
    client = context.session.client.return_value
    client.get_paginator.return_value.paginate.return_value = [{"Children": [child]}]
    from awsherlock.collectors.common import InvalidResponse
    with pytest.raises(InvalidResponse):
        discover_ou_accounts(client, [OU])
