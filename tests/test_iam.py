"""IAM policy, credential and error fixtures; no real credentials."""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
from urllib.parse import quote
import json

import pytest
from typer.testing import CliRunner

from awsherlock.aws.context import ScanContext
from awsherlock.cli import app
from awsherlock.collectors.iam import collect_iam
from awsherlock.iam_facts import policy_statements
from awsherlock.models import Resource
from awsherlock.rules.iam import IAM_RULES
from test_s3 import aws_error

NOW = datetime(2026, 9, 15, tzinfo=timezone.utc)
POLICY = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::test/object"}]}


def resource(data):
    return Resource(service="iam", resource_type="user", account_id="123456789012", region=None,
                    resource_id="test-user", resource_arn=None, data=data)


@pytest.mark.parametrize("index,bad,good", [
    (0, ["arn:aws:iam::aws:policy/AdministratorAccess"], ["arn:aws:iam::123456789012:policy/AdministratorAccess"]),
    (1, policy_statements({"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "specific"}}), policy_statements(POLICY)),
    (2, policy_statements({"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}), policy_statements(POLICY)),
    (3, {"console": True, "mfa": False}, {"console": True, "mfa": True}),
    (4, {"active": True, "days": 91}, {"active": True, "days": 90}),
    (5, {"days": 91, "never_used": True}, {"days": 90, "never_used": False}),
])
def test_six_rules(index, bad, good):
    rule = IAM_RULES[index]
    assert rule.evaluate(resource({rule.required_fact: bad}))[0].id == f"AWSH-IAM-{index + 1:03}"
    assert rule.evaluate(resource({rule.required_fact: good})) == []
    with pytest.raises(ValueError):
        rule.evaluate(resource({}))


def test_policy_semantics():
    document = {"Statement": {"Effect": "Deny", "Action": "*", "Resource": "*"}}
    facts = policy_statements(quote(json.dumps(document)))
    assert IAM_RULES[1].evaluate(resource({"statements": facts})) == []
    assert IAM_RULES[2].evaluate(resource({"statements": facts})) == []
    facts = policy_statements({"Statement": {"Effect": "Allow", "NotAction": "iam:*", "NotResource": "specific", "Condition": {"StringEquals": {"secret-marker": "hidden"}}}})
    assert "secret-marker" not in repr(facts)
    assert IAM_RULES[1].evaluate(resource({"statements": facts}))
    assert IAM_RULES[2].evaluate(resource({"statements": facts}))


@pytest.mark.parametrize("document", [None, "bad-json", {}, {"Statement": [None]}, {"Statement": [{"Effect": "Allow", "Action": [], "Resource": "*"}]}])
def test_bad_policy(document):
    with pytest.raises(ValueError):
        policy_statements(document)


@pytest.fixture
def context():
    session = Mock()
    client = session.client.return_value
    user = {"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice",
            "AttachedManagedPolicies": [], "UserPolicyList": [{"PolicyDocument": POLICY}]}
    managed = {"PolicyName": "managed", "Arn": "arn:aws:iam::123456789012:policy/managed", "DefaultVersionId": "v2",
               "PolicyVersionList": [{"IsDefaultVersion": False, "VersionId": "v1", "Document": {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}},
                                     {"IsDefaultVersion": True, "VersionId": "v2", "Document": POLICY}]}
    pages = {
        "get_account_authorization_details": [{"UserDetailList": [user]}, {"Policies": [managed]}],
        "list_mfa_devices": [{"MFADevices": []}, {"MFADevices": [{"SerialNumber": "synthetic-mfa"}]}],
        "list_access_keys": [{"AccessKeyMetadata": [{"AccessKeyId": "synthetic-key-marker", "Status": "Active", "CreateDate": NOW - timedelta(days=100)}]}],
    }
    client.get_paginator.side_effect = lambda name: Mock(paginate=Mock(return_value=pages[name]))
    client.get_login_profile.return_value = {"LoginProfile": {"UserName": "alice"}}
    client.get_access_key_last_used.return_value = {"AccessKeyLastUsed": {}}
    return ScanContext("123456789012", "arn:aws:iam::123456789012:root", "aws", None, None, session)


def test_collection_pagination_and_default_version(context):
    result = collect_iam(context, now=NOW)
    assert not result.issues
    assert len(result.resources) == 3
    assert result.resources[0].data["console_mfa"] == {"console": True, "mfa": True}
    assert result.resources[1].data["key_age"]["days"] == 100
    assert result.resources[1].data["key_stale"]["days"] == 100
    assert result.resources[2].data["statements"] == policy_statements(POLICY)
    assert "synthetic-key-marker" not in repr(result)
    assert all(r.region is None for r in result.resources)
    context.session.client.assert_called_once_with("iam")


@pytest.mark.parametrize("method", ["get_login_profile", "get_access_key_last_used"])
def test_access_denied(context, method):
    getattr(context.session.client.return_value, method).side_effect = aws_error("AccessDenied")
    result = collect_iam(context, now=NOW)
    assert len(result.issues) == 1
    assert result.issues[0].message == "AccessDenied"
    assert "secret-marker" not in repr(result)
    assert len(result.resources) == 3


def test_no_console_profile(context):
    context.session.client.return_value.get_login_profile.side_effect = aws_error("NoSuchEntity")
    result = collect_iam(context, now=NOW)
    assert not result.issues
    assert not result.resources[0].data["console_mfa"]["console"]


def test_cli_iam(context, monkeypatch):
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    result = CliRunner().invoke(app, ["scan", "--services", "iam"])
    assert result.exit_code == 0
    assert "Scan coverage" in result.output and "COMPLETE" in result.output
    assert "synthetic-key-marker" not in result.output


def test_authorization_denied(context):
    context.session.client.return_value.get_paginator.side_effect = aws_error("AccessDenied")
    result = collect_iam(context, now=NOW)
    assert not result.resources
    assert result.issues[0].message == "AccessDenied"
