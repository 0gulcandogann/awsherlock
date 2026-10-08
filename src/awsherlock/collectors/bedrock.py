"""Read Amazon Bedrock Agents Classic and Runtime logging configuration."""

import re

from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import (
    AWS_ERRORS,
    CollectionIssue,
    CollectionResult,
    InvalidResponse,
    error_message,
    items,
    text_field,
)
from awsherlock.models import Resource


_AGENT_ID = re.compile(r"[0-9A-Za-z]{10}")
_GUARDRAIL_ID = re.compile(r"[a-z0-9]+")
_GUARDRAIL_VERSION = re.compile(r"(?:[0-9]{1,8}|DRAFT)")
_AGENT_STATUSES = frozenset({
    "CREATING", "PREPARING", "PREPARED", "NOT_PREPARED",
    "DELETING", "FAILED", "VERSIONING", "UPDATING",
})
_MODALITIES = (
    ("audioDataDeliveryEnabled", "audio"),
    ("embeddingDataDeliveryEnabled", "embedding"),
    ("imageDataDeliveryEnabled", "image"),
    ("textDataDeliveryEnabled", "text"),
    ("videoDataDeliveryEnabled", "video"),
)


def _optional_text(value: object) -> None:
    if not isinstance(value, str) or any(ord(character) < 32 or ord(character) == 127
                                         for character in value):
        raise InvalidResponse()


def _s3_destination(value: object) -> None:
    if not isinstance(value, dict):
        raise InvalidResponse()
    text_field(value.get("bucketName"))
    if "keyPrefix" in value:
        _optional_text(value["keyPrefix"])


def _cloudwatch_destination(value: object) -> None:
    if not isinstance(value, dict):
        raise InvalidResponse()
    text_field(value.get("logGroupName"))
    text_field(value.get("roleArn"))
    if "largeDataDeliveryS3Config" in value:
        _s3_destination(value["largeDataDeliveryS3Config"])


def _logging_configuration(response: object) -> dict:
    if not isinstance(response, dict):
        raise InvalidResponse()
    if "loggingConfig" not in response:
        return {"configured": False, "destinations": [], "modalities": []}
    configuration = response["loggingConfig"]
    if not isinstance(configuration, dict):
        raise InvalidResponse()
    destinations = []
    if "cloudWatchConfig" in configuration:
        _cloudwatch_destination(configuration["cloudWatchConfig"])
        destinations.append("cloudwatch")
    if "s3Config" in configuration:
        _s3_destination(configuration["s3Config"])
        destinations.append("s3")
    modalities = []
    for field, label in _MODALITIES:
        if field not in configuration:
            continue
        value = configuration[field]
        if type(value) is not bool:
            raise InvalidResponse()
        if value:
            modalities.append(label)
    return {"configured": True, "destinations": destinations, "modalities": modalities}


def _agent_resource(context: ScanContext, agent_id: str, response: object) -> Resource:
    if not isinstance(response, dict) or not isinstance(response.get("agent"), dict):
        raise InvalidResponse()
    agent = response["agent"]
    if agent.get("agentId") != agent_id or agent.get("agentVersion") != "DRAFT":
        raise InvalidResponse()
    expected_arn = (f"arn:{context.partition}:bedrock:{context.region}:"
                    f"{context.account_id}:agent/{agent_id}")
    if agent.get("agentArn") != expected_arn:
        raise InvalidResponse()
    status = agent.get("agentStatus")
    if status not in _AGENT_STATUSES:
        raise InvalidResponse()
    role_arn = text_field(agent.get("agentResourceRoleArn"))
    if re.fullmatch(
        rf"arn:{re.escape(context.partition)}:iam::{context.account_id}:role/[^\s*?]+",
        role_arn,
    ) is None:
        raise InvalidResponse()
    guardrail = agent.get("guardrailConfiguration")
    if guardrail is None:
        normalized_guardrail = {"identifier": None, "version": None}
    else:
        if not isinstance(guardrail, dict):
            raise InvalidResponse()
        identifier = guardrail.get("guardrailIdentifier")
        version = guardrail.get("guardrailVersion")
        if not isinstance(identifier, str) or not isinstance(version, str):
            raise InvalidResponse()
        identifier_is_arn = identifier == (
            f"arn:{context.partition}:bedrock:{context.region}:{context.account_id}:"
            f"guardrail/{identifier.rsplit('/', 1)[-1]}"
        ) and _GUARDRAIL_ID.fullmatch(identifier.rsplit("/", 1)[-1]) is not None
        if (_GUARDRAIL_ID.fullmatch(identifier) is None and not identifier_is_arn) or (
            _GUARDRAIL_VERSION.fullmatch(version) is None
        ):
            raise InvalidResponse()
        normalized_guardrail = {"identifier": identifier, "version": version}
    return Resource(
        service="bedrock",
        resource_type="agent",
        account_id=context.account_id,
        region=context.region,
        resource_id=agent_id,
        resource_arn=expected_arn,
        data={
            "agent_status": status,
            "agent_version": "DRAFT",
            "execution_role_arn": role_arn,
            "guardrail_configuration": normalized_guardrail,
        },
    )


def collect_bedrock(context: ScanContext) -> CollectionResult:
    result = CollectionResult()
    if context.region is None:
        result.issues.append(CollectionIssue(
            None, "Region", "Configure an AWS region for Amazon Bedrock",
        ))
        return result

    regional = Resource(
        service="bedrock",
        resource_type="regional-settings",
        account_id=context.account_id,
        region=context.region,
        resource_id=f"bedrock:{context.region}",
        resource_arn=None,
    )
    result.resources.append(regional)

    try:
        client = context.client("bedrock", region_name=context.region)
        regional.data["model_invocation_logging_configuration"] = _logging_configuration(
            client.get_model_invocation_logging_configuration()
        )
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(
            regional.resource_id,
            "GetModelInvocationLoggingConfiguration",
            error_message(error),
        ))

    seen: set[str] = set()
    try:
        client = context.client("bedrock-agent", region_name=context.region)
        for page in client.get_paginator("list_agents").paginate():
            for summary in items(page, "agentSummaries"):
                if not isinstance(summary, dict):
                    result.issues.append(CollectionIssue(None, "ListAgents", "Invalid AWS response"))
                    continue
                agent_id = summary.get("agentId")
                if not isinstance(agent_id, str) or _AGENT_ID.fullmatch(agent_id) is None:
                    result.issues.append(CollectionIssue(None, "ListAgents", "Invalid AWS response"))
                    continue
                if agent_id in seen:
                    result.issues.append(CollectionIssue(agent_id, "ListAgents", "Invalid AWS response"))
                    continue
                seen.add(agent_id)
                try:
                    result.resources.append(_agent_resource(
                        context, agent_id, client.get_agent(agentId=agent_id),
                    ))
                except AWS_ERRORS as error:
                    result.resources.append(Resource(
                        service="bedrock",
                        resource_type="agent",
                        account_id=context.account_id,
                        region=context.region,
                        resource_id=agent_id,
                        resource_arn=None,
                    ))
                    result.issues.append(CollectionIssue(agent_id, "GetAgent", error_message(error)))
        result.completed_operations.append("ListAgents")
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(None, "ListAgents", error_message(error)))

    result.resources.sort(key=lambda resource: (
        resource.resource_type, resource.resource_id, resource.resource_arn or "",
    ))
    result.issues.sort(key=lambda issue: (
        issue.operation, issue.resource_id or "", issue.message,
    ))
    return result
