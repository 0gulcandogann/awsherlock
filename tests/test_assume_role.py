"""AssumeRole behavior with synthetic credentials and no AWS access."""

import traceback
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError, CredentialRetrievalError, NoCredentialsError
from typer.testing import CliRunner

from awsherlock.aws.session import SessionError, create_scan_context
from awsherlock.cli import app

ROLE = "arn:aws:iam::999999999999:role/team/Audit"
CREDENTIALS = {
    "AccessKeyId": "synthetic-access-marker",
    "SecretAccessKey": "synthetic-secret-marker",
    "SessionToken": "synthetic-token-marker",
}


@pytest.fixture
def sessions(monkeypatch: pytest.MonkeyPatch) -> tuple[Mock, Mock, Mock]:
    source = Mock(profile_name="production", region_name="eu-central-1")
    target = Mock()
    source.client.return_value.assume_role.return_value = {"Credentials": CREDENTIALS.copy()}
    target.client.return_value.get_caller_identity.return_value = {
        "Account": "999999999999",
        "Arn": "arn:aws:sts::999999999999:assumed-role/Audit/AWSherlock",
    }
    target.region_name = "eu-central-1"
    target.client.return_value.get_paginator.return_value.paginate.return_value = [{"Buckets": []}]
    factory = Mock(side_effect=[source, target])
    monkeypatch.setattr("awsherlock.aws.session.boto3.Session", factory)
    return factory, source, target


@pytest.mark.parametrize("partition", ["aws", "aws-cn", "aws-us-gov"])
@pytest.mark.parametrize("use_source", [False, True])
def test_assume_role(sessions: tuple[Mock, Mock, Mock], partition: str, use_source: bool) -> None:
    factory, source, target = sessions
    role = ROLE.replace(":aws:", f":{partition}:")
    target.client.return_value.get_caller_identity.return_value["Arn"] = (
        f"arn:{partition}:sts::999999999999:assumed-role/Audit/AWSherlock"
    )
    if use_source:
        factory.side_effect = [target]
        context = create_scan_context(role=role, source_session=source)
    else:
        context = create_scan_context(profile="production", role=role)
        assert factory.call_args_list[0].kwargs == {"profile_name": "production"}
    source.client.return_value.assume_role.assert_called_once_with(
        RoleArn=role, RoleSessionName="AWSherlock",
    )
    factory.assert_called_with(
        aws_access_key_id=CREDENTIALS["AccessKeyId"],
        aws_secret_access_key=CREDENTIALS["SecretAccessKey"],
        aws_session_token=CREDENTIALS["SessionToken"], region_name="eu-central-1",
    )
    assert context.session is target
    assert context.account_id == "999999999999"
    assert context.profile == "production"
    assert context.partition == partition
    source.client.return_value.get_caller_identity.assert_not_called()
    source.get_credentials.assert_not_called()
    assert "marker" not in repr(context)


def test_cli_success(sessions: tuple[Mock, Mock, Mock], caplog: pytest.LogCaptureFixture) -> None:
    _, source, target = sessions
    target.client.return_value.get_caller_identity.return_value["Arn"] = (
        "arn:aws:sts::999999999999:assumed-role/Audit/custom-session"
    )
    result = CliRunner().invoke(app, [
        "scan", "--role", ROLE, "--role-session-name", "custom-session",
        "--external-id", "external-marker",
        "--services", "s3",
    ])
    assert result.exit_code == 0
    assert "Account: 999999999999" in result.output
    assert "Scan coverage" in result.output and "COMPLETE" in result.output
    source.client.return_value.assume_role.assert_called_once_with(
        RoleArn=ROLE, RoleSessionName="custom-session", ExternalId="external-marker",
    )
    assert "marker" not in result.output + caplog.text


@pytest.mark.parametrize("use_source", [False, True])
def test_selected_region_survives_assume_role(sessions, use_source):
    factory, source, target = sessions
    source.region_name = target.region_name = "eu-west-1"
    if use_source:
        factory.side_effect = [target]
        context = create_scan_context(source_session=source, role=ROLE)
    else:
        context = create_scan_context(profile="production", role=ROLE, region="eu-west-1")
        assert factory.call_args_list[0].kwargs["region_name"] == "eu-west-1"
    assert factory.call_args.kwargs["region_name"] == "eu-west-1"
    assert context.region == "eu-west-1"


@pytest.mark.parametrize("options", [
    {"role": ""}, {"role": "sensitive-marker"},
    {"role": "arn:aws:sts::999999999999:assumed-role/Audit/session"},
    {"role": "arn:aws:iam::123:role/Audit"},
    {"role": "arn:aws:iam:eu-central-1:999999999999:role/Audit"},
    {"role": ROLE + "\n"}, {"role": ROLE + "*"},
    {"role": "arn:aws:iam::999999999999:user/Audit"},
    {"role": ROLE, "role_session_name": "x"},
    {"role": ROLE, "role_session_name": "x" * 65},
    {"role": ROLE, "external_id": "sensitive marker"},
    {"role": ROLE, "external_id": ""},
    {"role_session_name": "session"}, {"external_id": "external-marker"},
    {"profile": "production", "source_session": Mock()},
])
def test_invalid_options(sessions: tuple[Mock, Mock, Mock], options: dict) -> None:
    factory, _, _ = sessions
    with pytest.raises(SessionError) as raised:
        create_scan_context(**options)
    factory.assert_not_called()
    assert "marker" not in str(raised.value)


@pytest.mark.parametrize("response", [
    None, [], {}, {"Credentials": None}, {"Credentials": []},
    *[{"Credentials": {**CREDENTIALS, key: value}}
      for key in CREDENTIALS for value in (None, "", 123)],
])
def test_invalid_credentials(sessions: tuple[Mock, Mock, Mock], response: object) -> None:
    factory, source, target = sessions
    source.client.return_value.assume_role.return_value = response
    with pytest.raises(SessionError, match="invalid AssumeRole credentials"):
        create_scan_context(role=ROLE)
    assert factory.call_count == 1
    target.client.assert_not_called()


@pytest.mark.parametrize("stage", ["source", "assume", "target", "identity"])
@pytest.mark.parametrize("error,expected", [
    (ClientError({"Error": {"Code": "AccessDenied", "Message": "secret-marker"}}, "AssumeRole"), "AccessDenied"),
    (ClientError({"Error": {"Code": "ExpiredToken", "Message": "secret-marker"}}, "AssumeRole"), "expired or invalid"),
    (ClientError({"Error": {"Code": "Unknown", "Message": "secret-marker"}}, "AssumeRole"), "AWS rejected"),
    (NoCredentialsError(), "missing or incomplete"),
    (CredentialRetrievalError(provider="test", error_msg="secret-marker"), "AWS session failed"),
])
def test_failures(
    sessions: tuple[Mock, Mock, Mock], stage: str, error: Exception, expected: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    factory, source, target = sessions
    if stage == "source":
        factory.side_effect = error
    elif stage == "target":
        factory.side_effect = [source, error]
    else:
        call = (source.client.return_value.assume_role if stage == "assume"
                else target.client.return_value.get_caller_identity)
        call.side_effect = error
    with pytest.raises(SessionError, match=expected) as raised:
        create_scan_context(role=ROLE)
    assert "marker" not in "".join(traceback.format_exception(raised.value)) + caplog.text


@pytest.mark.parametrize("arn", [
    "arn:aws:iam::999999999999:user/test",
    "arn:aws-cn:sts::999999999999:assumed-role/Audit/AWSherlock",
    "arn:aws:sts::999999999999:assumed-role/Other/AWSherlock",
    "arn:aws:sts::999999999999:assumed-role/Audit/other",
    "arn:aws:sts::123456789012:assumed-role/Audit/AWSherlock",
])
def test_wrong_target(sessions: tuple[Mock, Mock, Mock], arn: str) -> None:
    _, _, target = sessions
    target.client.return_value.get_caller_identity.return_value = {
        "Account": arn.split(":")[4], "Arn": arn,
    }
    with pytest.raises(SessionError, match="does not match the requested role"):
        create_scan_context(role=ROLE)


def test_cli_access_denied(sessions: tuple[Mock, Mock, Mock]) -> None:
    _, source, _ = sessions
    source.client.return_value.assume_role.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "secret-marker"}}, "AssumeRole",
    )
    result = CliRunner().invoke(app, ["scan", "--role", ROLE])
    assert result.exit_code == 1
    assert "AccessDenied" in result.stderr
    assert "AssumeRole" in result.stderr
    assert "marker" not in result.output
    assert "Account:" not in result.output
    assert "PASS" not in result.output
