"""Bounded CloudTrail attribution; credential/session correlators stay in memory."""

import json
import re
import time
from datetime import datetime, timedelta
from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import CollectionResult

from awsherlock.collectors.common import AWS_ERRORS, InvalidResponse, CollectionIssue, items, text_field, error_message
from awsherlock.identity_config import IDENTITY_ARN


def _principal(identity: dict) -> str | None:
    issuer = identity.get("sessionContext", {}).get("sessionIssuer", {})
    arn = issuer.get("arn") if identity.get("type") in {"AssumedRole", "FederatedUser"} else identity.get("arn")
    if isinstance(arn, str) and (IDENTITY_ARN.fullmatch(arn) or re.fullmatch(r"arn:[a-z0-9-]+:iam::[0-9]{12}:root", arn)):
        return arn
    return None


def normalize_activity(events: list[dict], region: str) -> dict[str, list[dict]]:
    """Session matches require an exact in-memory key or unambiguous session ARN."""
    edges = {}
    for event in events:
        if event.get("errorCode") or event.get("eventSource") != "sts.amazonaws.com":
            continue
        operation = event.get("eventName")
        if operation not in {"AssumeRole", "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML"}:
            continue
        request, response = event.get("requestParameters"), event.get("responseElements")
        if not isinstance(request, dict) or not isinstance(response, dict):
            continue
        target = request.get("roleArn")
        if not isinstance(target, str) or not IDENTITY_ARN.fullmatch(target) or ":role/" not in target:
            continue
        identity = event.get("userIdentity", {})
        if not isinstance(identity, dict):
            continue
        caller = _principal(identity)
        credentials = response.get("credentials", {})
        assumed = response.get("assumedRoleUser", {})
        keys = [credentials.get("accessKeyId") if isinstance(credentials, dict) else None,
                assumed.get("arn") if isinstance(assumed, dict) else None]
        edge = {"target": target, "caller": caller, "source_keys": [identity.get("accessKeyId"), identity.get("arn")],
                "caller_account": identity.get("accountId"),
                "mechanism": "oidc" if operation == "AssumeRoleWithWebIdentity" else ("federation" if operation == "AssumeRoleWithSAML" else "assume_role"),
                "time": text_field(event.get("eventTime"))}
        for key in keys:
            if isinstance(key, str) and key:
                edges.setdefault(key, []).append(edge)

    def edge_for(keys, timestamp):
        for key in keys:
            candidates = [edge for edge in edges.get(key, []) if edge["time"] <= timestamp]
            if len(candidates) == 1:
                return candidates[0]
        return None

    result = {}
    for event in events:
        identity = event.get("userIdentity")
        if not isinstance(identity, dict):
            raise InvalidResponse()
        principal = _principal(identity)
        if principal is None:
            continue
        timestamp = text_field(event.get("eventTime"))
        operation = text_field(event.get("eventName"))
        mechanism = {"IAMUser": "iam_user", "AssumedRole": "assume_role", "AWSService": "aws_service",
                     "FederatedUser": "federation", "IdentityCenterUser": "human_session"}.get(identity.get("type"), "unknown")
        attribution = "caller_observed" if identity.get("type") == "IAMUser" else "issuer_only"
        caller = principal if attribution == "caller_observed" else None
        caller_account = identity.get("accountId") if attribution == "caller_observed" else None
        chain = []
        edge = edge_for([identity.get("accessKeyId"), identity.get("arn")], timestamp)
        visited = set()
        if edge is not None and edge["target"] == principal:
            mechanism = edge["mechanism"]
            while edge is not None and edge["target"] not in visited and len(chain) < 8:
                visited.add(edge["target"])
                if edge["caller"] is None:
                    caller = None
                    if isinstance(edge["caller_account"], str) and re.fullmatch(r"[0-9]{12}", edge["caller_account"]):
                        caller_account = edge["caller_account"]
                        attribution = "caller_account_observed"
                    break
                caller = edge["caller"]
                chain.append(caller)
                attribution = "caller_observed"
                caller_account = caller.split(":")[4]
                parent = edge_for(edge["source_keys"], edge["time"])
                edge = parent if parent is not None and parent["target"] == caller else None
        session_context = identity.get("sessionContext", {})
        if not isinstance(session_context, dict):
            raise InvalidResponse()
        record = {"time": timestamp, "region": region, "mechanism": mechanism, "caller_arn": caller,
                  "caller_account": caller_account if isinstance(caller_account, str) and re.fullmatch(r"[0-9]{12}", caller_account) else None,
                  "operation": operation, "source_identity_present": bool(session_context.get("sourceIdentity")),
                  "attribution": attribution, "chain": chain,
                  "chain_complete": caller is not None and (":user/" in caller or caller.endswith(":root"))}
        result.setdefault(principal, []).append(record)
    return result


def collect_identity_activity(context: ScanContext, result: CollectionResult, now: datetime) -> None:
    options = context.identity_options
    regions = options.regions or ((context.region,) if context.region else ())
    all_events = {}
    complete = bool(regions)
    deadline = time.monotonic() + options.max_seconds
    pages_used = 0
    if not regions:
        result.issues.append(CollectionIssue(None, "IdentityEvents", "Configure a region for identity event history"))
    for region in regions:
        events = []
        unmapped_actor = False
        try:
            client = context.client("cloudtrail", region_name=region)
            token = None
            seen_tokens = set()
            next_request = 0.0
            while True:
                remaining = deadline - time.monotonic()
                if pages_used >= options.max_pages or remaining <= 0:
                    complete = False
                    result.issues.append(CollectionIssue(None, "IdentityEvents", "Event history page/time budget exhausted"))
                    break
                delay = max(0, next_request - time.monotonic())
                if delay >= remaining:
                    complete = False
                    result.issues.append(CollectionIssue(None, "IdentityEvents", "Event history time budget exhausted"))
                    break
                if delay:
                    time.sleep(delay)
                params = {"StartTime": now - timedelta(days=options.days), "EndTime": now, "MaxResults": 50}
                if token is not None:
                    params["NextToken"] = token
                pages_used += 1
                response = client.lookup_events(**params)
                next_request = time.monotonic() + 0.55
                for raw in items(response, "Events"):
                    if not isinstance(raw, dict) or not isinstance(raw.get("CloudTrailEvent"), str):
                        raise InvalidResponse()
                    try:
                        event = json.loads(raw["CloudTrailEvent"])
                    except (ValueError, RecursionError):
                        raise InvalidResponse() from None
                    if not isinstance(event, dict):
                        raise InvalidResponse()
                    identity = event.get("userIdentity", {})
                    if isinstance(identity, dict) and identity.get("type") in {"IdentityCenterUser", "Unknown"}:
                        complete = False
                        unmapped_actor = True
                    events.append(event)
                token = response.get("NextToken")
                if token is None:
                    break
                token = text_field(token)
                if token in seen_tokens:
                    raise InvalidResponse()
                seen_tokens.add(token)
        except AWS_ERRORS as error:
            complete = False
            result.issues.append(CollectionIssue(None, "IdentityEvents", error_message(error)))
        if unmapped_actor:
            result.issues.append(CollectionIssue(None, "IdentityEvents", "An audit actor cannot be mapped to an IAM role/user in " + region + "; actor attribution is unknown"))
        try:
            normalized = normalize_activity(events, region)
            for arn, activity in normalized.items():
                all_events.setdefault(arn, []).extend(activity)
        except (InvalidResponse, TypeError, AttributeError, KeyError) as error:
            complete = False
            result.issues.append(CollectionIssue(None, "IdentityEvents", "Invalid AWS response"))
    for resource in result.resources:
        if resource.resource_type in {"role", "user"}:
            resource.data["identity_activity"] = {"days": options.days, "regions": list(regions), "complete": complete,
                                                  "events": all_events.get(resource.resource_arn, [])}
