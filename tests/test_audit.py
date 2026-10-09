from unittest.mock import Mock
import json
import pytest
from awsherlock.aws.context import ScanContext
from awsherlock.collectors.cloudtrail import collect_cloudtrail
from awsherlock.collectors.kms import collect_kms
from awsherlock.models import Resource
from awsherlock.rules.audit import CLOUDTRAIL_RULES, KMS_RULES
from test_s3 import aws_error

SETTINGS = {"IsMultiRegionTrail": True, "IncludeGlobalServiceEvents": True, "LogFileValidationEnabled": True, "IsOrganizationTrail": True}


@pytest.mark.parametrize("rule,bad,good", [
    (CLOUDTRAIL_RULES[0], False, True),
    (CLOUDTRAIL_RULES[1], {**SETTINGS, "IsMultiRegionTrail": False}, SETTINGS),
    (CLOUDTRAIL_RULES[2], {**SETTINGS, "LogFileValidationEnabled": False}, SETTINGS),
    (KMS_RULES[0], {"eligible": True, "enabled": False}, {"eligible": True, "enabled": True}),
    (KMS_RULES[1], [{"effect": "Allow", "broad_principal": True}], [{"effect": "Allow", "broad_principal": False}]),
])
def test_five_rules(rule, bad, good):
    r = Resource(service=rule.service, resource_type="test", account_id="123456789012", region="eu-west-1", resource_id="test", resource_arn=None, data={rule.required_fact: bad})
    assert rule.evaluate(r)
    r.data[rule.required_fact] = good
    assert not rule.evaluate(r)
    r.data.clear()
    with pytest.raises(ValueError):
        rule.evaluate(r)


@pytest.fixture
def context():
    session = Mock()
    client = session.client.return_value
    client.describe_trails.return_value = {"trailList": [{"Name": "organization", "TrailARN": "arn:aws:cloudtrail:us-east-1:999999999999:trail/org", "HomeRegion": "us-east-1", "S3BucketName": "audit", **SETTINGS}]}
    client.get_trail_status.return_value = {"IsLogging": True}
    client.get_event_selectors.return_value = {"EventSelectors": [{"IncludeManagementEvents": True}]}
    client.get_paginator.return_value.paginate.return_value = [{"Keys": [{"KeyId": "key-1"}]}, {"Keys": [{"KeyId": "key-2"}]}]
    client.describe_key.return_value = {"KeyMetadata": {"Arn": "arn:aws:kms:eu-west-1:123456789012:key/test", "KeyManager": "CUSTOMER", "KeySpec": "SYMMETRIC_DEFAULT", "Origin": "AWS_KMS", "KeyState": "Enabled", "KeyUsage": "ENCRYPT_DECRYPT"}}
    client.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
    client.get_key_policy.return_value = {"Policy": json.dumps({"Statement": {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*", "Resource": "*"}})}
    return ScanContext("123456789012", "arn:aws:iam::123456789012:root", "aws", None, "eu-west-1", session)


def test_home_region_organization_trail(context):
    result = collect_cloudtrail(context)
    assert not result.issues
    assert result.resources[-1].data["usable_trail"] is True
    context.session.client.assert_any_call("cloudtrail", region_name="us-east-1")
    context.session.client.return_value.describe_trails.assert_called_once_with(includeShadowTrails=True)


def test_empty_trails(context):
    context.session.client.return_value.describe_trails.return_value = {"trailList": []}
    result = collect_cloudtrail(context)
    assert CLOUDTRAIL_RULES[0].evaluate(result.resources[0])


def test_trail_denied_is_unknown(context):
    context.session.client.return_value.get_trail_status.side_effect = aws_error("AccessDenied")
    result = collect_cloudtrail(context)
    assert result.issues
    assert "usable_trail" not in result.resources[-1].data


def test_kms_pagination_root_policy_and_rotation(context):
    result = collect_kms(context)
    assert len(result.resources) == 2
    assert not result.issues
    assert not KMS_RULES[1].evaluate(result.resources[0])
    context.session.client.return_value.get_key_rotation_status.assert_any_call(KeyId="key-1")


@pytest.mark.parametrize("field,value", [("Origin", "EXTERNAL"), ("KeySpec", "RSA_2048"), ("KeyManager", "AWS"), ("KeyState", "Disabled")])
def test_ineligible_rotation(context, field, value):
    context.session.client.return_value.describe_key.return_value["KeyMetadata"][field] = value
    result = collect_kms(context)
    assert not result.issues
    assert not KMS_RULES[0].evaluate(result.resources[0])
    context.session.client.return_value.get_key_rotation_status.assert_not_called()


def test_kms_access_denied(context):
    context.session.client.return_value.get_key_rotation_status.side_effect = aws_error("AccessDenied")
    result = collect_kms(context)
    assert len(result.issues) == 2
    assert "policy" in result.resources[0].data
    assert "rotation" not in result.resources[0].data
    assert "secret-marker" not in repr(result)
