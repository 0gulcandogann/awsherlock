"""Session tests use mocked SDK calls and synthetic account metadata."""

import traceback
from unittest.mock import Mock

import pytest
from botocore.exceptions import (
    ClientError, CredentialRetrievalError, EndpointConnectionError,
    NoCredentialsError, PartialCredentialsError, ProfileNotFound,
)

from awsherlock.aws.session import SessionError, create_scan_context


@pytest.fixture
def session_factory(monkeypatch: pytest.MonkeyPatch) -> Mock:
    session = Mock()
    session.profile_name = "default"
    session.region_name = "eu-central-1"
    session.client.return_value.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/test",
        "UserId": "synthetic-user",
    }
    factory = Mock(return_value=session)
    monkeypatch.setattr("awsherlock.aws.session.boto3.Session", factory)
    return factory


@pytest.mark.parametrize("profile", [None, "production"])
def test_session_context(session_factory: Mock, profile: str | None) -> None:
    session = session_factory.return_value
    session.profile_name = profile or "environment-profile"
    context = create_scan_context(profile)

    session_factory.assert_called_once_with(profile_name=profile)
    session.client.assert_called_once_with("sts")
    session.client.return_value.get_caller_identity.assert_called_once_with()
    assert context.session is session
    assert context.account_id == "123456789012"
    assert context.caller_arn == "arn:aws:iam::123456789012:user/test"
    assert context.partition == "aws"
    assert context.region == "eu-central-1"
    assert context.profile == session.profile_name
    assert "session=" not in repr(context)
    session.get_credentials.assert_not_called()


@pytest.mark.parametrize("region", ["eu-west-1", "us-gov-west-1", "cn-north-1"])
def test_explicit_region_overrides_sdk_configuration(session_factory, region):
    session_factory.return_value.region_name = region
    context = create_scan_context("production", region=region)
    session_factory.assert_called_once_with(profile_name="production", region_name=region)
    assert context.region == context.session.region_name == region


@pytest.mark.parametrize("region", ["", "EU-WEST-1", "eu-west-1\n", "eu-west-1,us-east-1", "bad\x1b[2J"])
def test_invalid_region_fails_before_sdk(session_factory, region):
    with pytest.raises(SessionError, match="Invalid AWS region syntax"):
        create_scan_context(region=region)
    session_factory.assert_not_called()


def test_source_region_mismatch_is_rejected_without_mutation(session_factory):
    source = session_factory.return_value
    with pytest.raises(SessionError, match="must match"):
        create_scan_context(source_session=source, region="eu-west-1")
    source.client.assert_not_called()
    assert source.region_name == "eu-central-1"


@pytest.mark.parametrize("partition", ["aws", "aws-cn", "aws-us-gov"])
@pytest.mark.parametrize("principal", ["iam::123456789012:root", "sts::123456789012:assumed-role/a/b"])
def test_identity_partitions(session_factory: Mock, partition: str, principal: str) -> None:
    session = session_factory.return_value
    session.region_name = None
    session.client.return_value.get_caller_identity.return_value["Arn"] = f"arn:{partition}:{principal}"
    context = create_scan_context()
    assert context.partition == partition
    assert context.region is None


@pytest.mark.parametrize("identity", [
    None, [], {}, {"Account": 123456789012},
    {"Account": "123", "Arn": "invalid"},
    {"Account": "123456789012"},
    {"Account": "123456789012", "Arn": 123},
    {"Account": "123456789012", "Arn": "arn:aws:iam::999999999999:root"},
    {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:root\n"},
    {"Account": "123456789012", "Arn": "invalid-sensitive-marker"},
])
def test_malformed_identity(session_factory: Mock, identity: object) -> None:
    session_factory.return_value.client.return_value.get_caller_identity.return_value = identity
    with pytest.raises(SessionError, match="invalid caller identity response") as raised:
        create_scan_context()
    assert "sensitive-marker" not in str(raised.value)


@pytest.mark.parametrize("stage", ["session", "client", "identity"])
@pytest.mark.parametrize("error,expected", [
    (NoCredentialsError(), "missing or incomplete"),
    (PartialCredentialsError(provider="test", cred_var="sensitive-marker"), "missing or incomplete"),
    (ProfileNotFound(profile="sensitive-marker"), "profile not found"),
    (CredentialRetrievalError(provider="test", error_msg="sensitive-marker"), "AWS session failed"),
    (EndpointConnectionError(endpoint_url="https://sensitive-marker.invalid"), "AWS session failed"),
])
def test_sdk_errors(session_factory: Mock, stage: str, error: Exception, expected: str) -> None:
    target = {
        "session": session_factory,
        "client": session_factory.return_value.client,
        "identity": session_factory.return_value.client.return_value.get_caller_identity,
    }[stage]
    target.side_effect = error
    with pytest.raises(SessionError, match=expected) as raised:
        create_scan_context()
    assert "sensitive-marker" not in "".join(traceback.format_exception(raised.value))


@pytest.mark.parametrize("code,expected", [
    ("AccessDenied", "AccessDenied"),
    ("AccessDeniedException", "AccessDenied"),
    ("ExpiredToken", "expired or invalid"),
    ("InvalidClientTokenId", "expired or invalid"),
    ("SignatureDoesNotMatch", "expired or invalid"),
    ("sensitive-marker", "AWS rejected"),
])
def test_api_errors(session_factory: Mock, code: str, expected: str) -> None:
    session_factory.return_value.client.return_value.get_caller_identity.side_effect = ClientError(
        {"Error": {"Code": code, "Message": "sensitive-marker"}}, "GetCallerIdentity",
    )
    with pytest.raises(SessionError, match=expected) as raised:
        create_scan_context()
    assert "sensitive-marker" not in "".join(traceback.format_exception(raised.value))
