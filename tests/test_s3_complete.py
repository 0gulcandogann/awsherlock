"""Day 6 rule semantics and partial collection regression tests."""

from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.collectors.s3 import collect_s3
from awsherlock.models import Resource
from awsherlock.rules.s3 import S3_RULES
from test_s3 import context, aws_error, ENCRYPTION, LOGGING  # Reuse the synthetic fixture.


@pytest.mark.parametrize("index,value,count", [
    (1, ["AES256"], 0), (1, ["aws:kms"], 0), (1, ["aws:kms:dsse"], 0),
    (1, None, 1), (1, ["unknown"], 1),
    (2, "Enabled", 0), (2, "Suspended", 1), (2, None, 1),
    (3, {"TargetBucket": "logs", "TargetPrefix": ""}, 0), (3, None, 1),
    (4, False, 0), (4, None, 0), (4, True, 1),
])
def test_rule_fixtures(index: int, value: object, count: int) -> None:
    rule = S3_RULES[index]
    resource = Resource(service="s3", resource_type="bucket", resource_id="test-bucket",
                        resource_arn=None, account_id="123456789012", region="us-east-1",
                        data={rule.required_fact: value})
    findings = rule.evaluate(resource)
    assert len(findings) == count
    if findings:
        assert findings[0].id == f"AWSH-S3-00{index + 1}"
        assert findings[0].evidence[rule.required_fact] == value
        assert findings[0].to_dict()["account_id"] == resource.account_id


@pytest.mark.parametrize("index", range(5))
def test_missing_fact_is_error(index: int) -> None:
    resource = Resource(service="s3", resource_type="bucket", resource_id="test-bucket",
                        resource_arn=None, account_id="123456789012", region=None)
    with pytest.raises(ValueError):
        S3_RULES[index].evaluate(resource)


@pytest.mark.parametrize("index,value", [(1, []), (1, [None]), (2, "bad"), (3, {}), (4, "false")])
def test_malformed_facts(index: int, value: object) -> None:
    rule = S3_RULES[index]
    resource = Resource(service="s3", resource_type="bucket", resource_id="test-bucket",
                        resource_arn=None, account_id="123456789012", region=None,
                        data={rule.required_fact: value})
    with pytest.raises(ValueError):
        rule.evaluate(resource)


@pytest.mark.parametrize("method,fact", [
    ("get_bucket_encryption", "encryption"), ("get_bucket_versioning", "versioning"),
    ("get_bucket_logging", "logging"), ("get_bucket_policy_status", "policy_public"),
])
def test_access_denied_preserves_other_checks(context, monkeypatch, method: str, fact: str) -> None:
    client = context.session.client.return_value
    getattr(client, method).side_effect = aws_error("AccessDenied")
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    result = CliRunner().invoke(app, ["scan", "--services", "s3"])
    assert result.exit_code == 1
    assert "AccessDenied" in result.output
    assert "PARTIAL" in result.output
    assert "4 checks evaluated" in result.output
    assert "PASS" not in result.output
    assert "secret-marker" not in result.output


@pytest.mark.parametrize("method,response", [
    ("get_bucket_encryption", {}), ("get_bucket_encryption", {"ServerSideEncryptionConfiguration": {"Rules": []}}),
    ("get_bucket_versioning", {"Status": None}), ("get_bucket_versioning", {"Status": "unknown"}),
    ("get_bucket_logging", {"LoggingEnabled": {}}), ("get_bucket_logging", {"LoggingEnabled": None}),
    ("get_bucket_policy_status", {}), ("get_bucket_policy_status", {"PolicyStatus": {"IsPublic": "false"}}),
])
def test_invalid_responses(context, method: str, response: object) -> None:
    getattr(context.session.client.return_value, method).return_value = response
    collection = collect_s3(context)
    assert len(collection.issues) == 1
    assert collection.issues[0].message == "Invalid AWS response"
    assert len(collection.resources[0].data) == 5


def test_absent_settings_and_cli_findings(context, monkeypatch) -> None:
    client = context.session.client.return_value
    client.get_bucket_encryption.side_effect = aws_error("ServerSideEncryptionConfigurationNotFoundError")
    client.get_bucket_versioning.return_value = {}
    client.get_bucket_logging.return_value = {}
    client.get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": True}}
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    result = CliRunner().invoke(app, ["scan", "--services", "s3"])
    assert result.exit_code == 0
    for number in ("002", "003", "004", "005"):
        assert f"AWSH-S3-{number}" in result.output
    assert "5 checks evaluated" in result.output
    assert "COMPLETE" in result.output


def test_missing_policy_is_not_denial(context) -> None:
    context.session.client.return_value.get_bucket_policy_status.side_effect = aws_error("NoSuchBucketPolicy")
    result = collect_s3(context)
    assert not result.issues
    assert result.resources[0].data["policy_public"] is None
    assert S3_RULES[-1].evaluate(result.resources[0]) == []


def test_duplicate_buckets_and_client_reuse(context) -> None:
    client = context.session.client.return_value
    client.get_paginator.return_value.paginate.return_value = [
        {"Buckets": [{"Name": "first"}, {"Name": "second"}]},
        {"Buckets": [{"Name": "first"}]},
    ]
    result = collect_s3(context)
    assert len(result.resources) == 2
    assert not result.issues
    assert context.session.client.call_count == 3  # Listing, account controls, regional client.
    for method in ("get_bucket_location", "get_public_access_block", "get_bucket_encryption",
                   "get_bucket_versioning", "get_bucket_logging", "get_bucket_policy_status"):
        assert getattr(client, method).call_count == 2
    assert not client.get_object.called
    assert not client.get_bucket_policy.called
