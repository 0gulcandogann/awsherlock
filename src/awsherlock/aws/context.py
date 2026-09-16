"""Account metadata and the shared AWS session for a scan."""

from dataclasses import dataclass, field

from boto3.session import Session
from botocore.config import Config
from botocore.client import BaseClient


@dataclass(frozen=True)
class ScanContext:
    """In-memory context; the session must not be included in reports."""

    account_id: str
    caller_arn: str
    partition: str
    profile: str | None
    region: str | None
    session: Session = field(repr=False, compare=False)
    client_config: Config | None = field(default=None, repr=False, compare=False)

    def client(self, service_name: str, **options: object) -> BaseClient:
        """Use the authenticated session with scan-specific request configuration."""
        if self.client_config is not None:
            options.setdefault("config", self.client_config)
        return self.session.client(service_name, **options)
