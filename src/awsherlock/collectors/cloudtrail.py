"""Trails visible in the configured region, including organization/shadow trails."""

from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import AWS_ERRORS, CollectionIssue, CollectionResult, InvalidResponse, collect_fact, error_message, items, text_field
from awsherlock.models import Resource
from awsherlock.cloudtrail_facts import management_context


def collect_cloudtrail(context: ScanContext) -> CollectionResult:
    result = CollectionResult()
    if context.region is None:
        result.issues.append(CollectionIssue(None, "Region", "Configure an AWS region for CloudTrail"))
        return result
    try:
        client = context.client("cloudtrail", region_name=context.region)
        trails = items(client.describe_trails(includeShadowTrails=True), "trailList")
        seen = set()
        clients = {context.region: client}
        usable = []
        unknown = False
        for trail in trails:
            name = None
            try:
                if not isinstance(trail, dict):
                    raise InvalidResponse()
                name, arn = text_field(trail.get("Name")), text_field(trail.get("TrailARN"))
                if arn in seen:
                    continue
                seen.add(arn)
                home = text_field(trail.get("HomeRegion"))
                resource = Resource(service="cloudtrail", resource_type="trail", account_id=context.account_id,
                                    region=home, resource_id=name, resource_arn=arn)
                result.resources.append(resource)
                def settings():
                    keys = ("IsMultiRegionTrail", "IncludeGlobalServiceEvents", "LogFileValidationEnabled", "IsOrganizationTrail")
                    if any(type(trail.get(key)) is not bool for key in keys):
                        raise InvalidResponse()
                    return {key: trail[key] for key in keys}
                collect_fact(result, resource, "trail_settings", "TrailSettings", settings)
                def status():
                    bucket = text_field(trail.get("S3BucketName"))
                    cache = context.trail_status_cache
                    key = (context.account_id, context.caller_arn, home, arn)
                    cached = cache.get(key) if cache is not None else None
                    if cached is None:
                        if home not in clients:
                            clients[home] = context.client("cloudtrail", region_name=home)
                        response = clients[home].get_trail_status(Name=arn)
                        if not isinstance(response, dict) or type(response.get("IsLogging")) is not bool:
                            raise InvalidResponse()
                        cached = {"logging": response["IsLogging"],
                                  "delivery_error": bool(response.get("LatestDeliveryError"))}
                        if cache is not None:
                            cache[key] = cached
                    return {**cached, "destination": bucket}
                collect_fact(result, resource, "trail_status", "GetTrailStatus", status)
                def selectors():
                    cache = context.trail_selector_cache
                    key = (context.account_id, context.caller_arn, home, arn)
                    cached = cache.get(key) if cache is not None else None
                    if cached is None:
                        if home not in clients:
                            clients[home] = context.client("cloudtrail", region_name=home)
                        cached = management_context(clients[home].get_event_selectors(TrailName=arn))
                        if cache is not None:
                            cache[key] = cached
                    resource.data["management_excluded_sources"] = list(cached["management_excluded_sources"])
                    return cached["management_events"]
                collect_fact(result, resource, "management_events", "GetEventSelectors", selectors)
                if all(fact in resource.data for fact in ("trail_status", "trail_settings", "management_events")):
                    status_data = resource.data["trail_status"]
                    covers_region = home == context.region or resource.data["trail_settings"]["IsMultiRegionTrail"]
                    usable.append(status_data["logging"] and not status_data["delivery_error"]
                                  and covers_region and resource.data["management_events"])
                else:
                    unknown = True
            except AWS_ERRORS as error:
                unknown = True
                result.issues.append(CollectionIssue(name, "TrailMetadata", error_message(error)))
        summary = Resource(service="cloudtrail", resource_type="regional_summary", account_id=context.account_id,
                           region=context.region, resource_id=context.account_id, resource_arn=None)
        if any(usable) or not unknown:
            summary.data["usable_trail"] = any(usable)
        result.resources.append(summary)
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(None, "DescribeTrails", error_message(error)))
    return result
