"""S3 collector/rule/CLI tests use synthetic facts and mocked AWS calls."""

from dataclasses import replace
from unittest.mock import Mock

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from botocore.stub import Stubber
from typer.testing import CliRunner

from awsherlock.aws.context import ScanContext
from awsherlock.cli import app
from awsherlock.collectors.s3 import collect_s3
from awsherlock.models import Resource
from awsherlock.rules.s3 import S3PublicAccessRule
from awsherlock.rules.s3 import S3_RULES

FLAGS = dict.fromkeys(("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True)
ENCRYPTION = {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}
LOGGING = {"LoggingEnabled": {"TargetBucket": "audit-logs", "TargetPrefix": ""}}


def stub_extra_reads(stub: Stubber, name: str, account: str) -> None:
    params = {"Bucket": name, "ExpectedBucketOwner": account}
    stub.add_response("get_bucket_encryption", ENCRYPTION, params)
    stub.add_response("get_bucket_versioning", {"Status": "Enabled"}, params)
    stub.add_response("get_bucket_logging", LOGGING, params)
    stub.add_response("get_bucket_policy_status", {"PolicyStatus": {"IsPublic": False}}, params)


def aws_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "secret-marker"}}, "Test")


@pytest.fixture
def context() -> ScanContext:
    session = Mock()
    client = session.client.return_value
    client.get_paginator.return_value.paginate.return_value = [{"Buckets": [{"Name": "test-bucket"}]}]
    client.get_bucket_location.return_value = {"LocationConstraint": None}
    client.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": FLAGS.copy()}
    client.get_bucket_encryption.return_value = ENCRYPTION
    client.get_bucket_versioning.return_value = {"Status": "Enabled"}
    client.get_bucket_logging.return_value = LOGGING
    client.get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": False}}
    account_client = Mock()
    account_client.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": dict.fromkeys(FLAGS, False)}
    session.client.side_effect = lambda service, **kwargs: account_client if service == "s3control" else session.client.return_value
    return ScanContext("123456789012", "arn:aws:iam::123456789012:root", "aws", None, None, session)


@pytest.mark.parametrize("configuration,expected", [
    (FLAGS, 0), (dict.fromkeys(FLAGS, False), 1), (None, 1),
    *[({**FLAGS, key: False}, 1) for key in FLAGS],
])
def test_rule(configuration: object, expected: int) -> None:
    resource = Resource(
        service="s3", resource_type="bucket", account_id="123456789012", region="us-east-1",
        resource_id="test-bucket", resource_arn="arn:aws:s3:::test-bucket",
        data={"public_access_block": configuration},
    )
    results = S3PublicAccessRule().evaluate(resource)
    assert len(results) == expected
    if results:
        assert results[0].id == "AWSH-S3-001"
        assert results[0].evidence["public_access_block"] == configuration
        assert "not confirmation" in results[0].description
        assert results[0].to_dict()["resource_arn"] == resource.resource_arn
    assert S3PublicAccessRule().evaluate(replace(resource, service="other")) == []


@pytest.mark.parametrize("data", [{}, {"public_access_block": {}}, {"public_access_block": {**FLAGS, "BlockPublicAcls": "true"}}])
def test_rule_rejects_unknown_facts(data: dict) -> None:
    resource = Resource(service="s3", resource_type="bucket", account_id="123456789012",
                        region=None, resource_id="test-bucket", resource_arn=None, data=data)
    with pytest.raises(ValueError):
        S3PublicAccessRule().evaluate(resource)


@pytest.mark.parametrize("location,region", [(None, "us-east-1"), ("EU", "eu-west-1"), ("ap-south-1", "ap-south-1")])
@pytest.mark.parametrize("partition", ["aws", "aws-cn", "aws-us-gov"])
def test_regions_and_shared_session(context: ScanContext, location: str | None, region: str, partition: str) -> None:
    context = replace(context, partition=partition)
    client = context.session.client.return_value
    client.get_bucket_location.return_value = {"LocationConstraint": location}
    result = collect_s3(context)
    assert not result.issues
    assert result.resources[0].region == region
    assert result.resources[0].resource_arn == f"arn:{partition}:s3:::test-bucket"
    context.session.client.assert_any_call("s3", region_name=region)
    client.get_public_access_block.assert_called_once_with(Bucket="test-bucket", ExpectedBucketOwner=context.account_id)


def test_missing_configuration(context: ScanContext) -> None:
    context.session.client.return_value.get_public_access_block.side_effect = aws_error("NoSuchPublicAccessBlockConfiguration")
    result = collect_s3(context)
    assert not result.issues
    assert len(S3PublicAccessRule().evaluate(result.resources[0])) == 1


@pytest.mark.parametrize("operation", ["get_bucket_location", "get_public_access_block"])
@pytest.mark.parametrize("error", [aws_error("AccessDenied"), aws_error("NoSuchBucket"), EndpointConnectionError(endpoint_url="secret-marker")])
def test_bucket_errors_continue(context: ScanContext, operation: str, error: Exception) -> None:
    client = context.session.client.return_value
    client.get_paginator.return_value.paginate.return_value = [{"Buckets": [{"Name": "first"}, {"Name": "second"}]}]
    success = {"LocationConstraint": None} if operation == "get_bucket_location" else {"PublicAccessBlockConfiguration": FLAGS}
    getattr(client, operation).side_effect = [error, success]
    result = collect_s3(context)
    expected = ["second"] if operation == "get_bucket_location" else ["first", "second"]
    assert [resource.resource_id for resource in result.resources] == expected
    assert len(result.issues) == 1
    assert result.issues[0].resource_id == "first"
    assert "marker" not in repr(result)


@pytest.mark.parametrize("response", [None, {}, {"PublicAccessBlockConfiguration": {}}, {"PublicAccessBlockConfiguration": {**FLAGS, "BlockPublicAcls": 1}}])
def test_malformed_block_response(context: ScanContext, response: object) -> None:
    context.session.client.return_value.get_public_access_block.return_value = response
    result = collect_s3(context)
    assert "public_access_block" not in result.resources[0].data
    assert result.issues[0].message == "Invalid AWS response"


@pytest.mark.parametrize("response", [{}, None, {"LocationConstraint": "secret-marker"}])
def test_malformed_location(context: ScanContext, response: object) -> None:
    context.session.client.return_value.get_bucket_location.return_value = response
    result = collect_s3(context)
    assert not result.resources
    assert result.issues


def test_pagination_failure_preserves_results(context: ScanContext) -> None:
    def pages():
        yield {"Buckets": [{"Name": "test-bucket"}]}
        raise aws_error("AccessDenied")
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = pages()
    result = collect_s3(context)
    assert len(result.resources) == 1
    assert result.issues[0].message == "AccessDenied"


def test_real_sdk_pagination(context: ScanContext) -> None:
    # Stubber validates request parameters and SDK pagination without network access.
    session = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name="us-east-1")
    client = session.client("s3")
    context.session.client.return_value = client
    with Stubber(client) as stub:
        stub.add_response("list_buckets", {"Buckets": [{"Name": "first"}], "ContinuationToken": "next"}, {"MaxBuckets": 1000})
        stub.add_response("get_bucket_location", {"LocationConstraint": "EU"}, {"Bucket": "first", "ExpectedBucketOwner": context.account_id})
        stub.add_response("get_public_access_block", {"PublicAccessBlockConfiguration": FLAGS}, {"Bucket": "first", "ExpectedBucketOwner": context.account_id})
        stub_extra_reads(stub, "first", context.account_id)
        stub.add_response("list_buckets", {"Buckets": [{"Name": "second"}]}, {"ContinuationToken": "next", "MaxBuckets": 1000})
        stub.add_response("get_bucket_location", {"LocationConstraint": "EU"}, {"Bucket": "second", "ExpectedBucketOwner": context.account_id})
        stub.add_response("get_public_access_block", {"PublicAccessBlockConfiguration": FLAGS}, {"Bucket": "second", "ExpectedBucketOwner": context.account_id})
        stub_extra_reads(stub, "second", context.account_id)
        result = collect_s3(context)
        stub.assert_no_pending_responses()
    assert not result.issues
    assert len(result.resources) == 2


@pytest.mark.parametrize("denied", [False, True])
def test_cli(context: ScanContext, monkeypatch: pytest.MonkeyPatch, denied: bool) -> None:
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    client = context.session.client.return_value
    if denied:
        client.get_public_access_block.side_effect = aws_error("AccessDenied")
    else:
        client.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": dict.fromkeys(FLAGS, False)}
    result = CliRunner().invoke(app, ["scan", "--services", "s3"])
    assert result.exit_code == (1 if denied else 0)
    assert ("AccessDenied" if denied else "AWSH-S3-001") in result.output
    assert "PASS" not in result.output
    assert "secret-marker" not in result.output


def test_empty_account(context: ScanContext, monkeypatch: pytest.MonkeyPatch) -> None:
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = [{"Buckets": []}]
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    result = CliRunner().invoke(app, ["scan", "--services", "s3"])
    assert result.exit_code == 0
    assert "0 findings   /   0 resources" in result.output


def test_cli_partial(context: ScanContext, monkeypatch: pytest.MonkeyPatch) -> None:
    client = context.session.client.return_value
    client.get_paginator.return_value.paginate.return_value = [{"Buckets": [{"Name": "first"}, {"Name": "second"}]}]
    client.get_public_access_block.side_effect = [aws_error("AccessDenied"), {"PublicAccessBlockConfiguration": dict.fromkeys(FLAGS, False)}]
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    result = CliRunner().invoke(app, ["scan", "--services", "s3"])
    assert result.exit_code == 1
    assert "PARTIAL" in result.output
    assert "AWSH-S3-001" in result.output
    assert "AccessDenied" in result.output


@pytest.mark.parametrize("page", [None, {}, {"Buckets": None}, {"Buckets": [{"Name": "bad\nname"}]}])
def test_invalid_listing(context: ScanContext, page: object) -> None:
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = [page]
    result = collect_s3(context)
    assert result.issues
    assert not result.resources


def test_list_access_denied(context: ScanContext) -> None:
    context.session.client.return_value.get_paginator.return_value.paginate.side_effect = aws_error("AccessDenied")
    result = collect_s3(context)
    assert not result.resources
    assert result.issues[0].message == "AccessDenied"


@pytest.mark.parametrize("services", ["unknown", "unknown,s3", "", "s3,"])
def test_unsupported_services(monkeypatch: pytest.MonkeyPatch, services: str) -> None:
    factory = Mock()
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    result = CliRunner().invoke(app, ["scan", "--services", services])
    assert result.exit_code == 2
    factory.assert_not_called()
