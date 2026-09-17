"""Local profile metadata through SDK config parsing, without authentication."""

from dataclasses import dataclass

from botocore.session import Session
from botocore.exceptions import BotoCoreError

from awsherlock.aws.session import SessionError


@dataclass(frozen=True)
class ProfileMetadata:
    name: str
    region: str | None


def list_profiles() -> list[ProfileMetadata]:
    """SDK parses config/shared credentials files; read only names and regions.

    Do not call get_credentials or create clients: credential_process, SSO and
    metadata providers must never execute during this local operation.
    """
    try:
        profiles = Session().full_config.get("profiles", {})
    except (BotoCoreError, OSError):
        raise SessionError("Could not read AWS profile configuration. Check your AWS config files.") from None
    return [ProfileMetadata(name, values.get("region") or None)
            for name, values in sorted(profiles.items())]
