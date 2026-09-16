"""Small shared collection results and safe AWS response helpers."""

from dataclasses import dataclass, field
from datetime import datetime
from collections.abc import Callable

from botocore.exceptions import (BotoCoreError, ClientError, ConnectTimeoutError,
                                ReadTimeoutError, EndpointConnectionError)

from awsherlock.models import JSONValue, Resource


@dataclass(frozen=True)
class CollectionIssue:
    resource_id: str | None
    operation: str
    message: str


@dataclass
class CollectionResult:
    resources: list[Resource] = field(default_factory=list)
    issues: list[CollectionIssue] = field(default_factory=list)


class InvalidResponse(ValueError):
    """Response lacks facts needed for a reliable evaluation."""


def error_message(error: Exception) -> str:
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code")
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
            return "AccessDenied"
        if code in {"Throttling", "ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded"}:
            return "AWS request throttled"
        if code in {"ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "SignatureDoesNotMatch"}:
            return "AWS credentials expired or invalid"
        return "AWS request failed"
    if isinstance(error, (ConnectTimeoutError, ReadTimeoutError)):
        return "AWS request timed out"
    if isinstance(error, EndpointConnectionError):
        return "AWS endpoint connection failed"
    return "Invalid AWS response" if isinstance(error, InvalidResponse) else "AWS SDK request failed"


AWS_ERRORS = (BotoCoreError, ClientError, InvalidResponse)


def items(response: object, key: str) -> list:
    if not isinstance(response, dict) or not isinstance(response.get(key), list):
        raise InvalidResponse()
    return response[key]


def text_field(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise InvalidResponse()
    return value


def age_days(value: object, now: datetime) -> int:
    if not isinstance(value, datetime) or value.utcoffset() is None or value > now:
        raise InvalidResponse()
    return (now - value).days


def collect_fact(result: CollectionResult, resource: Resource, key: str, operation: str,
                 read: Callable[[], JSONValue]) -> None:
    try:
        resource.data[key] = read()
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(resource.resource_id, operation, error_message(error)))
