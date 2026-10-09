from dataclasses import replace
from unittest.mock import Mock

import boto3
import pytest
from botocore.stub import Stubber

from awsherlock.collectors.common import InvalidResponse
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.organization import scan_organization
from awsherlock.reporting import render_html
from awsherlock.resource_policy import statements
from awsherlock.snapshot import SnapshotError, snapshot_from_dict
from test_s3 import context
from test_snapshot import snapshot


def test_sdk_organization_empty_page_with_next_token(context):
    client = boto3.client("organizations", region_name="us-east-1",
                          aws_access_key_id="synthetic", aws_secret_access_key="synthetic")
    with Stubber(client) as stub:
        stub.add_response("list_accounts", {"Accounts": [], "NextToken": "next-page"}, {})
        stub.add_response("list_accounts", {"Accounts": [{"Id": "000000000001", "Name": "Example", "State": "CLOSED"}]}, {"NextToken": "next-page"})
        context.session.client.return_value = client
        report = scan_organization(context, ["s3"])
        assert len(report.metadata["accounts"]) == 1
        assert report.incomplete
        stub.assert_no_pending_responses()


def test_invalid_account_snapshot_does_not_stop_next(context, monkeypatch, snapshot):
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = [{"Accounts": [
        {"Id": "000000000001", "Name": "One", "State": "ACTIVE"},
        {"Id": "000000000002", "Name": "Two", "State": "ACTIVE"}]}]
    monkeypatch.setattr("awsherlock.organization.create_scan_context", Mock(return_value=context))
    monkeypatch.setattr("awsherlock.organization.capture_snapshot", Mock(side_effect=[SnapshotError("Invalid normalized snapshot data"), snapshot]))
    report = scan_organization(context, ["s3"])
    assert len(report.coverage) == 2
    assert report.coverage[0]["issues"][0]["operation"] == "SnapshotValidation"


@pytest.mark.parametrize("document", ["not json", {}, {"Statement": None},
    {"Statement": {"Effect": "Allow", "Principal": "*", "Action": []}},
    {"Statement": {"Effect": "Allow", "Principal": "*", "NotPrincipal": "*", "Action": "*"}},
    {"Statement": {"Effect": "Allow", "Principal": "*", "Action": "*", "Condition": "bad"}}])
def test_malformed_policy_never_becomes_safe(document):
    with pytest.raises(InvalidResponse):
        statements(document)


@pytest.mark.parametrize("service,kind,data", [
    ("ec2", "instance", {"metadata": {"endpoint": "enabled", "tokens": "unknown"}}),
    ("ec2", "security-group", {"ingress": [{"protocol": "tcp", "from": 80, "to": 20, "cidrs": ["0.0.0.0/0"]}]}),
    ("ec2", "volume", {"encrypted": "false"}),
    ("lambda", "function", {"urls": [{"arn": "example", "auth": "unknown"}]}),
    ("kms", "key", {"rotation": {"eligible": "false", "reason": "example"}}),
])
def test_invalid_offline_facts_rejected(snapshot, service, kind, data):
    raw = snapshot.to_dict()
    resource = raw["services"]["s3"]["resources"][0]
    resource.update(service=service, resource_type=kind, data=data)
    raw["services"] = {service: {"resources": [resource], "issues": []}}
    with pytest.raises(SnapshotError):
        snapshot_from_dict(raw)


def test_escaping_account_attributes_and_issues(snapshot):
    report = evaluate_snapshot(snapshot)
    payload = '\"><img src=x onerror=alert(1)>'
    report.metadata["accounts"] = [{"account_id": "000000000001", "name": payload, "state": "ACTIVE", "scan_status": "PARTIAL"}]
    report.findings[0] = replace(report.findings[0], resource_id=payload)
    report.coverage[0]["issues"][0]["message"] = payload
    html = render_html(report)
    assert "<img" not in html
    assert "&lt;img" in html
