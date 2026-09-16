"""Collect general-purpose S3 bucket facts, preserving visible failures."""

import re
from dataclasses import dataclass, field
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from awsherlock.aws.context import ScanContext
from awsherlock.models import JSONValue, Resource
from awsherlock.s3_facts import PUBLIC_ACCESS_FLAGS, validate_fact


@dataclass(frozen=True)
class CollectionIssue:
    resource_id: str | None
    operation: str
    message: str


@dataclass
class S3Collection:
    resources: list[Resource] = field(default_factory=list)
    issues: list[CollectionIssue] = field(default_factory=list)


class InvalidResponse(ValueError):
    """An AWS response cannot be safely normalized."""


def _message(error: Exception) -> str:
    if isinstance(error, ClientError):
        if error.response.get("Error", {}).get("Code") in {"AccessDenied", "AccessDeniedException"}:
            return "AccessDenied"
        return "AWS request failed"
    if isinstance(error, InvalidResponse):
        return "Invalid AWS response"
    return "AWS SDK request failed"


def _normalize(name: str, response: object) -> JSONValue:
    if not isinstance(response, dict):
        raise InvalidResponse()
    if name == "public_access_block":
        config = response.get("PublicAccessBlockConfiguration")
        if not isinstance(config, dict):
            raise InvalidResponse()
        value = {key: config.get(key) for key in PUBLIC_ACCESS_FLAGS}
    elif name == "encryption":
        config = response.get("ServerSideEncryptionConfiguration")
        if not isinstance(config, dict) or not isinstance(config.get("Rules"), list):
            raise InvalidResponse()
        value = []
        for rule in config["Rules"]:
            default = rule.get("ApplyServerSideEncryptionByDefault") if isinstance(rule, dict) else None
            if not isinstance(default, dict):
                raise InvalidResponse()
            value.append(default.get("SSEAlgorithm"))
    elif name == "versioning":
        if "Status" in response and response["Status"] is None:
            raise InvalidResponse()
        value = response.get("Status")
    elif name == "logging":
        if "LoggingEnabled" not in response:
            value = None
        else:
            config = response["LoggingEnabled"]
            if not isinstance(config, dict):
                raise InvalidResponse()
            value = {"TargetBucket": config.get("TargetBucket"), "TargetPrefix": config.get("TargetPrefix")}
    else:
        config = response.get("PolicyStatus")
        if not isinstance(config, dict) or type(config.get("IsPublic")) is not bool:
            raise InvalidResponse()
        value = config["IsPublic"]
    try:
        validate_fact(name, value)
    except ValueError:
        raise InvalidResponse() from None
    return value


def _bucket_facts(client: Any, name: str, account_id: str, result: S3Collection) -> dict[str, JSONValue]:
    # Missing facts are omitted; confirmed absence is None. Each API is read once.
    requests = (
        ("public_access_block", "get_public_access_block", "GetPublicAccessBlock", "NoSuchPublicAccessBlockConfiguration"),
        ("encryption", "get_bucket_encryption", "GetBucketEncryption", "ServerSideEncryptionConfigurationNotFoundError"),
        ("versioning", "get_bucket_versioning", "GetBucketVersioning", None),
        ("logging", "get_bucket_logging", "GetBucketLogging", None),
        ("policy_public", "get_bucket_policy_status", "GetBucketPolicyStatus", "NoSuchBucketPolicy"),
    )
    facts: dict[str, JSONValue] = {}
    for fact, method, operation, missing_code in requests:
        try:
            response = getattr(client, method)(Bucket=name, ExpectedBucketOwner=account_id)
            facts[fact] = _normalize(fact, response)
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code")
            if missing_code is not None and code == missing_code:
                facts[fact] = None
            else:
                result.issues.append(CollectionIssue(name, operation, _message(error)))
        except (BotoCoreError, InvalidResponse) as error:
            result.issues.append(CollectionIssue(name, operation, _message(error)))
    return facts


def collect_s3(context: ScanContext) -> S3Collection:
    result = S3Collection()
    seen: set[str] = set()
    clients = {}
    try:
        client = context.session.client("s3")
        pages = client.get_paginator("list_buckets").paginate(PaginationConfig={"PageSize": 1000})
        for page in pages:
            if not isinstance(page, dict) or not isinstance(page.get("Buckets"), list):
                raise InvalidResponse()
            for bucket in page["Buckets"]:
                name = bucket.get("Name") if isinstance(bucket, dict) else None
                if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{3,255}", name):
                    result.issues.append(CollectionIssue(None, "ListBuckets", "Invalid bucket name"))
                    continue
                if name in seen:
                    continue
                seen.add(name)
                operation = "GetBucketLocation"
                try:
                    location = client.get_bucket_location(Bucket=name, ExpectedBucketOwner=context.account_id)
                    if not isinstance(location, dict) or "LocationConstraint" not in location:
                        raise InvalidResponse()
                    region = location["LocationConstraint"]
                    region = "us-east-1" if region is None else "eu-west-1" if region == "EU" else region
                    if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", region):
                        raise InvalidResponse()
                    operation = "CreateRegionalClient"
                    if region not in clients:
                        clients[region] = context.session.client("s3", region_name=region)
                    result.resources.append(Resource(
                        service="s3", resource_type="bucket", account_id=context.account_id,
                        region=region, resource_id=name, resource_arn=f"arn:{context.partition}:s3:::{name}",
                        data=_bucket_facts(clients[region], name, context.account_id, result),
                    ))
                except (ClientError, BotoCoreError, InvalidResponse) as error:
                    result.issues.append(CollectionIssue(name, operation, _message(error)))
    except (ClientError, BotoCoreError, InvalidResponse) as error:
        result.issues.append(CollectionIssue(None, "ListBuckets", _message(error)))
    return result
