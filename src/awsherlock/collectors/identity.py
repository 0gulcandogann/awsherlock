"""Enrich IAM identities through the supplied session, within one collection."""

from datetime import datetime
from typing import Any
from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import CollectionResult

from awsherlock.collectors.common import AWS_ERRORS, CollectionIssue, InvalidResponse, items, error_message
from awsherlock.identity_config import approval_fact
from awsherlock.identity_facts import profile_fact, trust_fact, usage_fact
from awsherlock.iam_facts import policy_statements


def enrich_identities(context: ScanContext, result: CollectionResult, raw_entries: dict,
                      now: datetime, client: Any = None) -> None:
    client = client if client is not None else context.client("iam")
    policies = {resource.resource_arn: resource.data["statements"] for resource in result.resources
                if resource.resource_type == "policy" and "statements" in resource.data}
    groups = {resource.resource_id: resource for resource in result.resources if resource.resource_type == "group"}
    failed_policies = set()

    def managed(arn):
        if arn in failed_policies:
            raise InvalidResponse()
        if arn not in policies:
            try:
                response = client.get_policy(PolicyArn=arn)
                if not isinstance(response, dict) or not isinstance(response.get("Policy"), dict):
                    raise InvalidResponse()
                version = response["Policy"].get("DefaultVersionId")
                if not isinstance(version, str) or not version:
                    raise InvalidResponse()
                response = client.get_policy_version(PolicyArn=arn, VersionId=version)
                if not isinstance(response, dict) or not isinstance(response.get("PolicyVersion"), dict):
                    raise InvalidResponse()
                policies[arn] = policy_statements(response["PolicyVersion"].get("Document"))
            except AWS_ERRORS:
                failed_policies.add(arn)
                raise
        return policies[arn]

    for resource in result.resources:
        kind = resource.resource_type
        if kind not in {"role", "user"}:
            continue
        raw = raw_entries.get((kind, resource.resource_id), {})
        resource.data["identity_requested"] = True
        resource.data["identity_approval"] = approval_fact(context.account_id, resource.resource_arn, context.identity_options.inventory)
        try:
            tags = raw.get("Tags")
            if tags is None:
                operation = "list_role_tags" if kind == "role" else "list_user_tags"
                parameter = "RoleName" if kind == "role" else "UserName"
                tags = []
                for page in client.get_paginator(operation).paginate(**{parameter: resource.resource_id}):
                    tags.extend(items(page, "Tags"))
            if not isinstance(tags, list):
                raise InvalidResponse()
            resource.data["identity_profile"] = profile_fact(raw, tags, kind)
        except AWS_ERRORS as error:
            result.issues.append(CollectionIssue(resource.resource_id, "IdentityProfile", error_message(error)))
        if kind == "role":
            for fact, operation, read in (
                ("identity_trust", "RoleTrust", lambda: trust_fact(raw.get("AssumeRolePolicyDocument"))),
                ("identity_usage", "RoleLastUsed", lambda: usage_fact(raw, now)),
            ):
                try:
                    resource.data[fact] = read()
                except AWS_ERRORS as error:
                    result.issues.append(CollectionIssue(resource.resource_id, operation, error_message(error)))
        statements = list(resource.data.get("statements", []))
        attached = list(resource.data.get("attached", []))
        complete = "statements" in resource.data and "attached" in resource.data
        if kind == "user":
            memberships = raw.get("GroupList", [])
            if not isinstance(memberships, list) or any(not isinstance(name, str) for name in memberships):
                memberships = []
                complete = False
            for name in memberships:
                group = groups.get(name)
                if group is None or not {"attached", "statements"} <= group.data.keys():
                    complete = False
                    continue
                statements.extend(group.data["statements"])
                attached.extend(group.data["attached"])
        attached = list(dict.fromkeys(attached))
        for arn in attached:
            try:
                statements.extend(managed(arn))
            except AWS_ERRORS as error:
                complete = False
                result.issues.append(CollectionIssue(resource.resource_id, "IdentityManagedPolicy", error_message(error)))
        resource.data["identity_policy_context"] = {"complete": complete, "managed_sources": attached}
        # Known grants remain useful after failures; coverage records unresolved joins.
        resource.data["attached"] = attached
        resource.data["statements"] = statements
        if not complete:
            result.issues.append(CollectionIssue(resource.resource_id, "IdentityPolicyContext", "Policy associations are incomplete"))
    from awsherlock.collectors.identity_bindings import collect_identity_bindings
    collect_identity_bindings(context, result)
    if context.identity_options.events:
        from awsherlock.collectors.identity_events import collect_identity_activity
        collect_identity_activity(context, result, now)
    if context.identity_options.analyzers:
        from awsherlock.collectors.identity_analyzers import collect_identity_analyzers
        collect_identity_analyzers(context, result)
