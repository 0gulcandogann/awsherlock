"""Read DynamoDB table PITR configuration without reading table data."""

import re

from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import (AWS_ERRORS, CollectionIssue, CollectionResult,
                                          InvalidResponse, collect_fact, error_message, items)
from awsherlock.models import Resource


def _pitr_enabled(response: object) -> bool:
    if not isinstance(response, dict):
        raise InvalidResponse()
    backups = response.get("ContinuousBackupsDescription")
    if not isinstance(backups, dict) or backups.get("ContinuousBackupsStatus") != "ENABLED":
        raise InvalidResponse()
    recovery = backups.get("PointInTimeRecoveryDescription")
    if not isinstance(recovery, dict):
        raise InvalidResponse()
    status = recovery.get("PointInTimeRecoveryStatus")
    if status not in {"ENABLED", "DISABLED"}:
        raise InvalidResponse()
    return status == "ENABLED"


def collect_dynamodb(context: ScanContext) -> CollectionResult:
    result = CollectionResult()
    if context.region is None:
        result.issues.append(CollectionIssue(None, "Region", "Configure an AWS region for DynamoDB"))
        return result
    seen: set[str] = set()
    try:
        client = context.client("dynamodb", region_name=context.region)
        pages = client.get_paginator("list_tables").paginate()
        for page in pages:
            for name in items(page, "TableNames"):
                if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", name):
                    result.issues.append(CollectionIssue(None, "ListTables", "Invalid AWS response"))
                    continue
                if name in seen:
                    result.issues.append(CollectionIssue(f"table:{name}", "ListTables", "Invalid AWS response"))
                    continue
                seen.add(name)
                resource = Resource(service="dynamodb", resource_type="table",
                                    account_id=context.account_id, region=context.region,
                                    resource_id=f"table:{name}",
                                    resource_arn=(f"arn:{context.partition}:dynamodb:{context.region}:"
                                                  f"{context.account_id}:table/{name}"))
                result.resources.append(resource)
                collect_fact(result, resource, "pitr_enabled", "DescribeContinuousBackups",
                             lambda name=name: _pitr_enabled(client.describe_continuous_backups(TableName=name)))
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(None, "ListTables", error_message(error)))
    return result
