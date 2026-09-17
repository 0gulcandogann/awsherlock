"""Metadata-only AWS workload/AI role bindings; no runtime or secret reads."""

import time
import re
from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import CollectionResult

from awsherlock.collectors.common import AWS_ERRORS, InvalidResponse, CollectionIssue, items, text_field, error_message
from awsherlock.identity_config import IDENTITY_ARN


def collect_identity_bindings(context: ScanContext, result: CollectionResult) -> None:
    options = context.identity_options
    regions = options.regions or ((context.region,) if context.region else ())
    identities = {r.resource_arn: r for r in result.resources if r.resource_type == "role"}
    deadline = time.monotonic() + options.max_seconds
    reads = 0
    profiles = {}

    def check():
        nonlocal reads
        if reads >= options.max_pages or time.monotonic() >= deadline:
            raise InvalidResponse()
        reads += 1

    def pages(client, operation, key):
        iterator = iter(client.get_paginator(operation).paginate())
        while True:
            check()
            try:
                page = next(iterator)
            except StopIteration:
                return
            yield from items(page, key)
            if not any(page.get(token) for token in ("NextToken", "nextToken", "NextMarker", "Marker")):
                return

    def binding(service, region, arn, role):
        arn, role = text_field(arn), text_field(role)
        match = IDENTITY_ARN.fullmatch(role)
        if match is None or match[2] != context.account_id or match[3] != "role" or match[1] != context.partition:
            raise InvalidResponse()
        resource = identities.get(role)
        if resource is None:
            result.issues.append(CollectionIssue(arn, "IdentityBinding", "Workload role is absent from the IAM inventory"))
            return
        record = {"service": service, "region": region, "resource_arn": arn, "role_arn": role}
        if record not in resource.data["identity_bindings"]:
            resource.data["identity_bindings"].append(record)

    for resource in identities.values():
        resource.data["identity_bindings"] = []
    if not regions:
        result.issues.append(CollectionIssue(None, "IdentityBindings", "Configure regions for workload/AI role bindings"))
    for region in regions:
        operations = ["lambda", "ec2", *(["bedrock", "agentcore"] if options.ai_services else [])]
        for service in operations:
            try:
                if service == "lambda":
                    client = context.client("lambda", region_name=region)
                    for function in pages(client, "list_functions", "Functions"):
                        if not isinstance(function, dict):
                            raise InvalidResponse()
                        binding(service, region, function.get("FunctionArn"), function.get("Role"))
                elif service == "ec2":
                    client = context.client("ec2", region_name=region)
                    for reservation in pages(client, "describe_instances", "Reservations"):
                        for instance in items(reservation, "Instances"):
                            if not isinstance(instance, dict):
                                raise InvalidResponse()
                            profile = instance.get("IamInstanceProfile")
                            if profile is None:
                                continue
                            if not isinstance(profile, dict):
                                raise InvalidResponse()
                            profile_arn = text_field(profile.get("Arn"))
                            if not re.fullmatch(r"arn:" + re.escape(context.partition) + r":iam::" + context.account_id + r":instance-profile/[^\s*?]+", profile_arn):
                                raise InvalidResponse()
                            if profile_arn not in profiles:
                                check()
                                response = context.client("iam").get_instance_profile(InstanceProfileName=profile_arn.rsplit("/", 1)[-1])
                                if not isinstance(response, dict) or not isinstance(response.get("InstanceProfile"), dict):
                                    raise InvalidResponse()
                                if response["InstanceProfile"].get("Arn") != profile_arn:
                                    raise InvalidResponse()
                                profiles[profile_arn] = [text_field(role.get("Arn")) for role in items(response["InstanceProfile"], "Roles")]
                            instance_id = text_field(instance.get("InstanceId"))
                            for role in profiles[profile_arn]:
                                binding(service, region, f"arn:{context.partition}:ec2:{region}:{context.account_id}:instance/{instance_id}", role)
                elif service == "bedrock":
                    client = context.client("bedrock-agent", region_name=region)
                    for agent in pages(client, "list_agents", "agentSummaries"):
                        if not isinstance(agent, dict):
                            raise InvalidResponse()
                        check()
                        response = client.get_agent(agentId=text_field(agent.get("agentId")))
                        detail = response.get("agent") if isinstance(response, dict) else None
                        if not isinstance(detail, dict):
                            raise InvalidResponse()
                        binding(service, region, detail.get("agentArn"), detail.get("agentResourceRoleArn"))
                else:
                    client = context.client("bedrock-agentcore-control", region_name=region)
                    for runtime in pages(client, "list_agent_runtimes", "agentRuntimes"):
                        if not isinstance(runtime, dict):
                            raise InvalidResponse()
                        check()
                        detail = client.get_agent_runtime(agentRuntimeId=text_field(runtime.get("agentRuntimeId")))
                        if not isinstance(detail, dict):
                            raise InvalidResponse()
                        binding(service, region, detail.get("agentRuntimeArn"), detail.get("roleArn"))
            except AWS_ERRORS as error:
                result.issues.append(CollectionIssue(None, "IdentityBindings:" + service + ":" + region,
                                                     "Metadata page/time budget exhausted or invalid AWS response" if isinstance(error, InvalidResponse) else error_message(error)))
