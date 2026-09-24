"""Read GuardDuty detector status in one account and region."""

from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import (AWS_ERRORS, CollectionIssue, CollectionResult,
                                          InvalidResponse, error_message, items, text_field)
from awsherlock.models import Resource


def collect_guardduty(context: ScanContext) -> CollectionResult:
    result = CollectionResult()
    if context.region is None:
        result.issues.append(CollectionIssue(None, "Region", "Configure an AWS region for GuardDuty"))
        return result
    summary = Resource(service="guardduty", resource_type="regional-summary",
                       account_id=context.account_id, region=context.region,
                       resource_id=f"guardduty:{context.region}", resource_arn=None)
    result.resources.append(summary)
    enabled = False
    unknown = False
    seen: set[str] = set()
    try:
        client = context.client("guardduty", region_name=context.region)
        pages = client.get_paginator("list_detectors").paginate()
        for page in pages:
            for detector_id in items(page, "DetectorIds"):
                try:
                    detector_id = text_field(detector_id)
                    if detector_id in seen:
                        raise InvalidResponse()
                    seen.add(detector_id)
                    response = client.get_detector(DetectorId=detector_id)
                    if not isinstance(response, dict) or response.get("Status") not in {"ENABLED", "DISABLED"}:
                        raise InvalidResponse()
                    enabled |= response["Status"] == "ENABLED"
                except AWS_ERRORS as error:
                    unknown = True
                    result.issues.append(CollectionIssue(summary.resource_id, "GetDetector", error_message(error)))
        if enabled or not unknown:
            summary.data["enabled_detector_present"] = enabled
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(summary.resource_id, "ListDetectors", error_message(error)))
        if enabled:
            summary.data["enabled_detector_present"] = True
    return result
