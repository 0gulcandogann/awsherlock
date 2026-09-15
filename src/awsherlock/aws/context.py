"""Account metadata and the shared AWS session for a scan."""

from dataclasses import dataclass, field

from boto3.session import Session


@dataclass(frozen=True)
class ScanContext:
    """In-memory context; the session must not be included in reports."""

    account_id: str
    caller_arn: str
    partition: str
    profile: str | None
    region: str | None
    session: Session = field(repr=False, compare=False)
