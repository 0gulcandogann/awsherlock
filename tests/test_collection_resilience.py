"""Offline SDK transport retries and retention of successful pagination facts."""

import json
from unittest.mock import Mock

import pytest
from botocore.awsrequest import AWSResponse
from botocore.config import Config
from botocore.exceptions import ClientError, ReadTimeoutError
from botocore.stub import Stubber

from awsherlock.collectors.common import error_message
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.measurement import ScanMeasurements
from awsherlock.snapshot import capture_snapshot
from test_measurement import sdk_client, context, operation_counts


def response(status, body):
    raw = Mock()
    raw.stream.return_value = [json.dumps(body).encode()]
    return AWSResponse("https://synthetic.invalid", status,
                       {"content-type": "application/x-amz-json-1.1"}, raw)


@pytest.mark.parametrize("recovers", [True, False])
def test_sdk_throttling_retries_are_bounded_and_one_logical_call(monkeypatch, recovers):
    import boto3
    client = boto3.client("kms", region_name="eu-west-1", aws_access_key_id="synthetic",
                          aws_secret_access_key="synthetic",
                          config=Config(retries={"mode": "standard", "total_max_attempts": 3}))
    throttled = lambda: response(400, {"__type": "ThrottlingException", "message": "payload-secret"})
    replies = [throttled(), throttled(), response(200, {"Keys": []}) if recovers else throttled()]
    transport = Mock(side_effect=replies)
    monkeypatch.setattr(client._endpoint.http_session, "send", transport)
    monkeypatch.setattr("botocore.endpoint.time.sleep", lambda seconds: None)
    with ScanMeasurements() as measurements:
        report = evaluate_snapshot(capture_snapshot(context(client, measurements), ["kms"]))
        assert transport.call_count == 3
        assert operation_counts(measurements) == {"ListKeys": 1}
        assert report.incomplete is not recovers
        if not recovers:
            assert report.coverage[0]["issues"][0]["message"] == "AWS request throttled"
        assert "payload-secret" not in json.dumps(report.to_dict())


@pytest.mark.parametrize("code", ["AccessDeniedException", "ExpiredTokenException"])
def test_sdk_does_not_retry_nontransient_denial(monkeypatch, code):
    client = sdk_client("kms")
    transport = Mock(return_value=response(400, {"__type": code, "message": "secret"}))
    monkeypatch.setattr(client._endpoint.http_session, "send", transport)
    report = evaluate_snapshot(capture_snapshot(context(client), ["kms"]))
    assert transport.call_count == 1 and report.incomplete


@pytest.mark.parametrize("failure", ["AccessDeniedException", "ThrottlingException", "ExpiredTokenException"])
def test_successful_resources_survive_later_page_failure(failure):
    client = sdk_client("kms")
    key_id = "synthetic-key"
    arn = "arn:aws:kms:eu-west-1:123456789012:key/synthetic-key"
    with Stubber(client) as stub, ScanMeasurements() as measurements:
        stub.add_response("list_keys", {"Keys": [{"KeyId": key_id, "KeyArn": arn}],
                          "Truncated": True, "NextMarker": "page-two"}, {})
        stub.add_response("describe_key", {"KeyMetadata": {"KeyId": key_id, "Arn": arn,
                          "KeyManager": "AWS"}}, {"KeyId": key_id})
        stub.add_client_error("list_keys", failure, "secret", expected_params={"Marker": "page-two"})
        snapshot = capture_snapshot(context(client, measurements), ["kms"])
        report = evaluate_snapshot(snapshot)
        assert len(snapshot.services["kms"].resources) == 1
        assert report.coverage[0]["resources"] == 1
        assert report.coverage[0]["status"] == "PARTIAL"
        assert report.coverage[0]["evaluated"] == 1
        assert operation_counts(measurements) == {"ListKeys": 2, "DescribeKey": 1}


def test_timeout_message_is_specific_and_sanitized():
    assert error_message(ReadTimeoutError(endpoint_url="https://private-secret.invalid")) == "AWS request timed out"
    assert error_message(ClientError({"Error": {"Code": "arbitrary-secret-code"}}, "Test")) == "AWS request failed"
