"""Create AWS sessions using the standard SDK credential chain."""

import re

import boto3
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


def create_scan_context(profile: str | None = None) -> ScanContext:
    """Resolve caller identity without copying or persisting credentials."""
    try:
        session = boto3.Session(profile_name=profile)
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
            message = "AccessDenied: AWS caller identity could not be resolved."
        elif code in {
            "ExpiredToken", "ExpiredTokenException",
            "InvalidClientTokenId", "SignatureDoesNotMatch",
        }:
            message = "AWS credentials are expired or invalid. Refresh your AWS login or credentials."
        else:
            message = "AWS rejected the caller identity request. Check your AWS configuration."
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

    return ScanContext(
        account_id=account_id,
        caller_arn=caller_arn,
        partition=match.group(1),
        profile=session.profile_name,
        region=session.region_name,
        session=session,
    )
