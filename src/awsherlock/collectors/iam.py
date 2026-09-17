"""Collect IAM policy and credential metadata; never export access key IDs."""

from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import (
    AWS_ERRORS, CollectionIssue, CollectionResult, InvalidResponse, age_days,
    error_message, items, text_field,
)
from awsherlock.iam_facts import policy_statements
from awsherlock.models import Resource


def _resource(context: ScanContext, kind: str, name: str, arn: str | None, data: dict) -> Resource:
    return Resource(service="iam", resource_type=kind, account_id=context.account_id,
                    region=None, resource_id=name, resource_arn=arn, data=data)


def _user_credentials(client: Any, context: ScanContext, user: Resource,
                      result: CollectionResult, now: datetime) -> None:
    name = user.resource_id
    try:
        try:
            response = client.get_login_profile(UserName=name)
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
            user.data["console_mfa"] = {"console": False, "mfa": False}
        else:
            if not isinstance(response, dict) or not isinstance(response.get("LoginProfile"), dict):
                raise InvalidResponse()
            if response["LoginProfile"].get("UserName") != name:
                raise InvalidResponse()
            count = 0
            for page in client.get_paginator("list_mfa_devices").paginate(UserName=name):
                devices = items(page, "MFADevices")
                for device in devices:
                    if not isinstance(device, dict):
                        raise InvalidResponse()
                    text_field(device.get("SerialNumber"))
                count += len(devices)
            user.data["console_mfa"] = {"console": True, "mfa": count > 0}
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(name, "ConsoleMFA", error_message(error)))
    try:
        index = 0
        for page in client.get_paginator("list_access_keys").paginate(UserName=name):
            for key in items(page, "AccessKeyMetadata"):
                index += 1
                if not isinstance(key, dict) or key.get("Status") not in {"Active", "Inactive"}:
                    raise InvalidResponse()
                key_id = text_field(key.get("AccessKeyId"))
                age = age_days(key.get("CreateDate"), now)
                data = {"key_age": {"active": key["Status"] == "Active", "days": age}}
                if key["Status"] == "Active":
                    try:
                        response = client.get_access_key_last_used(AccessKeyId=key_id)
                        used = response.get("AccessKeyLastUsed") if isinstance(response, dict) else None
                        if not isinstance(used, dict):
                            raise InvalidResponse()
                        last = used.get("LastUsedDate")
                        # AWS returns no date for never-used keys; age provides the lower bound.
                        data["key_stale"] = {"days": age if last is None else age_days(last, now), "never_used": last is None}
                    except AWS_ERRORS as error:
                        result.issues.append(CollectionIssue(f"{name}/key-{index}", "GetAccessKeyLastUsed", error_message(error)))
                result.resources.append(_resource(context, "access_key", f"{name}/key-{index}", None, data))
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(name, "ListAccessKeys", error_message(error)))


def collect_iam(context: ScanContext, *, now: datetime | None = None) -> CollectionResult:
    now = now or datetime.now(timezone.utc)
    result = CollectionResult()
    raw_entries = {}
    client = None
    try:
        client = context.client("iam")
        pages = client.get_paginator("get_account_authorization_details").paginate()
        for page in pages:
            if not isinstance(page, dict):
                raise InvalidResponse()
            for kind, key, name_key, inline_key in (
                ("user", "UserDetailList", "UserName", "UserPolicyList"),
                ("group", "GroupDetailList", "GroupName", "GroupPolicyList"),
                ("role", "RoleDetailList", "RoleName", "RolePolicyList"),
                ("policy", "Policies", "PolicyName", "PolicyVersionList"),
            ):
                # AWS can omit empty lists; at least one recognized list must be present.
                if not any(key in page for key in ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")):
                    raise InvalidResponse()
                for entry in items({key: page.get(key, [])}, key):
                    name = None
                    try:
                        if not isinstance(entry, dict):
                            raise InvalidResponse()
                        name = text_field(entry.get(name_key))
                        arn = text_field(entry.get("Arn"))
                        resource = _resource(context, kind, name, arn, {})
                        result.resources.append(resource)
                        if kind in {"role", "user"}:
                            raw_entries[(kind, name)] = entry
                        try:
                            if kind != "policy":
                                resource.data["attached"] = [text_field(p.get("PolicyArn")) if isinstance(p, dict) else text_field(None)
                                                             for p in items(entry, "AttachedManagedPolicies")]
                            docs = items(entry, inline_key)
                            if kind == "policy":
                                docs = [p for p in docs if isinstance(p, dict) and p.get("IsDefaultVersion") is True]
                                if len(docs) != 1 or docs[0].get("VersionId") != entry.get("DefaultVersionId"):
                                    raise InvalidResponse()
                                statements = policy_statements(docs[0].get("Document"))
                            else:
                                statements = []
                                for policy in docs:
                                    if not isinstance(policy, dict):
                                        raise InvalidResponse()
                                    statements.extend(policy_statements(policy.get("PolicyDocument")))
                            resource.data["statements"] = statements
                        except AWS_ERRORS as error:
                            result.issues.append(CollectionIssue(name, "PolicyNormalization", error_message(error)))
                        if kind == "user":
                            _user_credentials(client, context, resource, result, now)
                    except AWS_ERRORS as error:
                        result.issues.append(CollectionIssue(name, "AuthorizationDetails", error_message(error)))
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(None, "GetAccountAuthorizationDetails", error_message(error)))
    if context.identity_options is not None:
        from awsherlock.collectors.identity import enrich_identities
        if client is not None:
            enrich_identities(context, result, raw_entries, now, client)
    return result
