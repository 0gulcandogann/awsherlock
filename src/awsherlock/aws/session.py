"""Create AWS sessions using the standard SDK credential chain."""

import re

import boto3
from boto3.session import Session
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    PartialCredentialsError,
    ProfileNotFound,
)

from awsherlock.aws.context import ScanContext


class SessionError(RuntimeError):
    """A safe, user-facing failure to establish an AWS scan context."""


def create_scan_context(
    profile: str | None = None,
    *,
    role: str | None = None,
    role_session_name: str | None = None,
    external_id: str | None = None,
    source_session: Session | None = None,
) -> ScanContext:
    """Resolve the source or assumed-role identity; keep credentials in memory."""
    role_match = _validate_role_options(role, role_session_name, external_id)
    if source_session is not None and profile is not None:
        raise SessionError("Specify either a source session or a profile, not both.")
    operation = "caller identity"
    try:
        session = source_session if source_session is not None else boto3.Session(profile_name=profile)
        source_profile = session.profile_name
        if role is not None:
            operation = "AssumeRole"
            parameters = {"RoleArn": role, "RoleSessionName": role_session_name or "AWSherlock"}
            if external_id is not None:
                parameters["ExternalId"] = external_id
            response = session.client("sts").assume_role(**parameters)
            credentials = response.get("Credentials") if isinstance(response, dict) else None
            if not isinstance(credentials, dict) or any(
                not isinstance(credentials.get(key), str) or not credentials[key].strip()
                for key in ("AccessKeyId", "SecretAccessKey", "SessionToken")
            ):
                raise SessionError("AWS returned an invalid AssumeRole credentials response.")
            session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=session.region_name,
            )
            operation = "caller identity"
        identity = session.client("sts").get_caller_identity()
    except ProfileNotFound:
        raise SessionError("AWS profile not found. Check your AWS configuration.") from None
    except (NoCredentialsError, PartialCredentialsError):
        raise SessionError(
            "AWS credentials are missing or incomplete. Configure the AWS SDK credential chain."
        ) from None
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code in {"AccessDenied", "AccessDeniedException"}:
            message = f"AccessDenied: AWS {operation} request was denied."
        elif code in {
            "ExpiredToken", "ExpiredTokenException",
            "InvalidClientTokenId", "SignatureDoesNotMatch",
        }:
            message = "AWS credentials are expired or invalid. Refresh your AWS login or credentials."
        else:
            message = f"AWS rejected the {operation} request. Check your AWS configuration."
        raise SessionError(message) from None
    except BotoCoreError:
        # SDK errors may embed credential-process output, tokens, or endpoint URLs.
        raise SessionError(
            "AWS session failed. Check your AWS configuration, login, and network connection."
        ) from None

    if not isinstance(identity, dict):
        raise SessionError("AWS returned an invalid caller identity response.")
    account_id = identity.get("Account")
    caller_arn = identity.get("Arn")
    if not isinstance(account_id, str) or not re.fullmatch(r"[0-9]{12}", account_id):
        raise SessionError("AWS returned an invalid caller identity response.")
    match = None
    if isinstance(caller_arn, str):
        match = re.fullmatch(
            r"arn:([a-z0-9-]+):(iam|sts)::([0-9]{12}):([^\s\x00-\x1f\x7f]+)",
            caller_arn,
        )
    if match is None or match.group(3) != account_id:
        raise SessionError("AWS returned an invalid caller identity response.")
    if role_match is not None:
        expected_arn = (
            f"arn:{role_match.group(1)}:sts::{role_match.group(2)}:assumed-role/"
            f"{role.rsplit('/', 1)[-1]}/{role_session_name or 'AWSherlock'}"
        )
        if caller_arn != expected_arn:
            raise SessionError("AWS caller identity does not match the requested role.")

    return ScanContext(
        account_id=account_id,
        caller_arn=caller_arn,
        partition=match.group(1),
        profile=source_profile,
        region=session.region_name,
        session=session,
    )


def _validate_role_options(
    role: str | None, role_session_name: str | None, external_id: str | None,
) -> re.Match[str] | None:
    """Reject malformed role input before accessing AWS; never echo its values."""
    if role is None:
        if role_session_name is not None or external_id is not None:
            raise SessionError("--role-session-name and --external-id require --role.")
        return None
    match = re.fullmatch(
        r"arn:([a-z0-9-]+):iam::([0-9]{12}):role/(?:[\x21-\x7e]+/)?([A-Za-z0-9_+=,.@-]{1,64})",
        role,
    )
    if match is None:
        raise SessionError("Invalid role ARN. Expected an IAM role ARN with a 12-digit account ID.")
    if role_session_name is not None and not re.fullmatch(r"[A-Za-z0-9_+=,.@-]{2,64}", role_session_name):
        raise SessionError("Invalid role session name. Use 2-64 letters, digits, or _+=,.@-.")
    if external_id is not None and not re.fullmatch(r"[A-Za-z0-9_+=,.@:/-]{2,1224}", external_id):
        raise SessionError("Invalid external ID format.")
    return match
