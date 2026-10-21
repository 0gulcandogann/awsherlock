"""The validation helper compares captured artifacts without AWS access."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from awsherlock.evaluation import evaluate_snapshot
from test_lead_delta import pair, EC2


def test_capture_replay_checker_detects_mismatch_without_exporting_payload(tmp_path):
    value = pair(EC2)
    snapshot = tmp_path / "capture.json"
    report = tmp_path / "live.json"
    snapshot.write_text(json.dumps(value.to_dict()), encoding="utf-8")
    data = evaluate_snapshot(value).to_dict()
    report.write_text(json.dumps(data), encoding="utf-8")
    script = Path(__file__).resolve().parents[1] / "scripts/validate_investigations.py"
    result = subprocess.run(
        [sys.executable, str(script), str(snapshot), "--report", str(report)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["capture_replay_match"] is True and output["investigations"] >= 1
    data["findings"][0]["evidence"] = {"private": "SECRET_SENTINEL"}
    report.write_text(json.dumps(data), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(script), str(snapshot), "--report", str(report)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "SECRET_SENTINEL" not in result.stdout + result.stderr
    assert "findings" in result.stderr


def test_inherited_sdk_retry_budget_is_bounded_without_network(monkeypatch):
    """Exercise the SDK retry loop with synthetic HTTP responses, not AWS."""
    import boto3
    from botocore.awsrequest import AWSResponse
    from botocore.exceptions import ClientError
    from awsherlock.aws.context import ScanContext
    from awsherlock.cli import request_options

    monkeypatch.setenv("AWS_RETRY_MODE", "standard")
    monkeypatch.setenv("AWS_MAX_ATTEMPTS", "3")
    monkeypatch.setattr("botocore.endpoint.time.sleep", lambda seconds: None)
    session = boto3.Session(
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic", region_name="eu-west-1"
    )
    context = ScanContext(
        account_id="123456789012",
        caller_arn="arn:aws:iam::123456789012:role/audit",
        partition="aws",
        profile=None,
        region="eu-west-1",
        session=session,
        **request_options(2, 3, None, None),
    )
    client = context.client("ec2", region_name="eu-west-1")
    assert client.meta.config.retries["total_max_attempts"] == 3
    assert client.meta.config.connect_timeout == 2 and client.meta.config.read_timeout == 3
    attempts = []

    class Body:
        def stream(self, **kwargs):
            yield (
                b"<Response><Errors><Error><Code>RequestLimitExceeded</Code>"
                b"<Message>synthetic throttling</Message></Error></Errors>"
                b"<RequestID>synthetic</RequestID></Response>"
            )

    def send(request):
        attempts.append(request)
        return AWSResponse(request.url, 503, {"content-type": "text/xml"}, Body())

    monkeypatch.setattr(client._endpoint.http_session, "send", send)
    with pytest.raises(ClientError) as error:
        client.describe_instances()
    assert error.value.response["Error"]["Code"] == "RequestLimitExceeded"
    assert len(attempts) == 3


@pytest.mark.parametrize(
    "code,expected",
    [
        ("SlowDown", "AWS request throttled"),
        ("RequestThrottled", "AWS request throttled"),
        ("RequestThrottledException", "AWS request throttled"),
        ("RequestTimeout", "AWS request timed out"),
        ("RequestTimeoutException", "AWS request timed out"),
    ],
)
def test_additional_aws_failures_remain_bounded_incomplete_evidence(code, expected):
    from botocore.exceptions import ClientError
    from awsherlock.collectors.common import CollectionIssue, CollectionResult, error_message
    from awsherlock.investigation_engine import build_investigations

    value = pair(EC2)
    error = ClientError(
        {"Error": {"Code": code, "Message": "SECRET_SENTINEL"}}, "DescribeInstances"
    )
    message = error_message(error)
    assert message == expected and "SECRET_SENTINEL" not in message
    value.services["ec2"] = CollectionResult(
        [], [CollectionIssue(None, "DescribeInstances", message)]
    )
    result = build_investigations(value)
    assert result.incomplete
    reason = "THROTTLED" if expected == "AWS request throttled" else "REQUEST_TIMEOUT"
    assert any(gap.reason_code == reason for gap in result.coverage_gaps)
