"""Metadata-only AWS workload/AI role bindings; no runtime or secret reads."""

import time
import re
from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import CollectionResult

from awsherlock.collectors.common import AWS_ERRORS, InvalidResponse, CollectionIssue, items, text_field, error_message
from awsherlock.identity_config import IDENTITY_ARN
from awsherlock.identity_validation import (
    agentcore_binding_identity,
    agentcore_endpoint_identity,
    agentcore_runtime_arn_identity,
    identity_binding_sort_key,
    is_agentcore_runtime_version,
)
from awsherlock.models import ResourceRef, Relationship, RelationshipEvidence, RelationshipType


def _collect_agentcore_endpoints(context, result, client, region, runtime_id,
                                runtime_arn, latest, check, binding, production_issues):
    """Read control-plane routes only; no runtime content is retained."""
    def issue(operation, error):
        production_issues.append(CollectionIssue(None, operation, error_message(error)))

    def read(operation, **params):
        method = getattr(client, operation, None)
        if not callable(method):
            raise InvalidResponse()
        check()
        return method(**params)

    seen, rejected, tokens = {}, set(), set()
    observed = {}
    token = None
    try:
        while True:
            params = {"agentRuntimeId": runtime_id}
            if token is not None:
                params["nextToken"] = token
            page = read("list_agent_runtime_endpoints", **params)
            for summary in items(page, "runtimeEndpoints"):
                identity = agentcore_endpoint_identity(summary, runtime_arn)
                if identity is None:
                    issue("ListAgentRuntimeEndpoints", InvalidResponse())
                    continue
                name, identifier = identity
                signature = (identifier, summary.get("liveVersion"), summary.get("targetVersion"))
                if name in seen:
                    if seen[name] != signature:
                        rejected.add(name)
                        observed.pop(name, None)
                        issue("ListAgentRuntimeEndpoints", InvalidResponse())
                    continue
                seen[name] = signature
                try:
                    detail = read("get_agent_runtime_endpoint", agentRuntimeId=runtime_id, endpointName=name)
                    if agentcore_endpoint_identity(detail, runtime_arn) != identity:
                        raise InvalidResponse()
                    source = ResourceRef(service="agentcore", resource_type="runtime-endpoint",
                                         account_id=context.account_id, region=region,
                                         resource_id=f"{runtime_id}:{name}",
                                         resource_arn=detail["agentRuntimeEndpointArn"])
                    routes = []
                    for field, fact in (("liveVersion", "live_version"), ("targetVersion", "target_version")):
                        version = detail.get(field)
                        if not is_agentcore_runtime_version(version):
                            issue("GetAgentRuntimeEndpoint", InvalidResponse())
                            continue
                        routes.append(Relationship(source=source, relationship_type=RelationshipType.USES,
                            target=ResourceRef(service="agentcore", resource_type="runtime-version",
                                account_id=context.account_id, region=region, resource_id=f"{runtime_id}:{version}"),
                            evidence=(RelationshipEvidence(service="agentcore", fact=fact,
                                                           operation="GetAgentRuntimeEndpoint"),)))
                    observed[name] = routes
                except AWS_ERRORS as error:
                    issue("GetAgentRuntimeEndpoint", error)
            token = page.get("nextToken")
            if token is None:
                break
            if (not isinstance(token, str) or not token or len(token) > 2048
                    or any(c.isspace() for c in token) or token in tokens):
                raise InvalidResponse()
            tokens.add(token)
    except AWS_ERRORS as error:
        issue("ListAgentRuntimeEndpoints", error)

    routes = [edge for name in sorted(observed) if name not in rejected for edge in observed[name]]
    result.relationship_observations.extend(routes)
    versions = sorted({edge.target.resource_id.rsplit(":", 1)[1] for edge in routes}, key=int)
    for version in versions:
        try:
            detail = latest if latest is not None and latest["agentRuntimeVersion"] == version else read(
                "get_agent_runtime", agentRuntimeId=runtime_id, agentRuntimeVersion=version)
            if (not isinstance(detail, dict) or detail.get("agentRuntimeId") != runtime_id
                    or detail.get("agentRuntimeArn") != runtime_arn
                    or detail.get("agentRuntimeVersion") != version):
                raise InvalidResponse()
            record = {"service": "agentcore", "region": region, "resource_arn": runtime_arn,
                      "resource_version": version, "role_arn": detail.get("roleArn")}
            identity = agentcore_binding_identity(record)
            if identity is None:
                raise InvalidResponse()
            role = next((r for r in result.resources if r.service == "iam" and r.resource_type == "role"
                         and r.resource_arn == record["role_arn"] and r.resource_id == identity[4]
                         and r.account_id == context.account_id and r.region is None), None)
            if role is None:
                raise InvalidResponse()
            binding("agentcore", region, runtime_arn, record["role_arn"], resource_version=version)
            result.relationship_observations.append(Relationship(
                source=ResourceRef(service="agentcore", resource_type="runtime-version",
                    account_id=context.account_id, region=region, resource_id=f"{runtime_id}:{version}"),
                relationship_type=RelationshipType.RUNS_AS,
                target=ResourceRef(service="iam", resource_type="role", account_id=context.account_id,
                    region=None, resource_id=identity[4], resource_arn=record["role_arn"]),
                evidence=(RelationshipEvidence(service="agentcore", fact="execution_role_arn",
                                               operation="GetAgentRuntime"),)))
        except AWS_ERRORS as error:
            issue("GetAgentRuntime", error)


def collect_identity_bindings(context: ScanContext, result: CollectionResult) -> None:
    options = context.identity_options
    regions = options.regions or ((context.region,) if context.region else ())
    identities = {r.resource_arn: r for r in result.resources if r.resource_type == "role"}
    deadline = time.monotonic() + options.max_seconds
    reads = 0
    profiles = {}
    production_issues = []

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

    def binding(service, region, arn, role, *, resource_version=None):
        arn, role = text_field(arn), text_field(role)
        match = IDENTITY_ARN.fullmatch(role)
        if match is None or match[2] != context.account_id or match[3] != "role" or match[1] != context.partition:
            raise InvalidResponse()
        resource = identities.get(role)
        if resource is None:
            result.issues.append(CollectionIssue(arn, "IdentityBinding", "Workload role is absent from the IAM inventory"))
            return
        record = {"service": service, "region": region, "resource_arn": arn, "role_arn": role}
        if resource_version is not None:
            record["resource_version"] = resource_version
            if agentcore_binding_identity(record) is None:
                raise InvalidResponse()
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
                        runtime_id = text_field(runtime.get("agentRuntimeId"))
                        runtime_arn = text_field(runtime.get("agentRuntimeArn"))
                        runtime_version = text_field(runtime.get("agentRuntimeVersion"))
                        if (
                            agentcore_runtime_arn_identity(runtime_arn)
                            != (context.partition, region, context.account_id, runtime_id)
                            or not is_agentcore_runtime_version(runtime_version)
                        ):
                            raise InvalidResponse()
                        detail = None
                        try:
                            check()
                            response = client.get_agent_runtime(
                                agentRuntimeId=runtime_id,
                                agentRuntimeVersion=runtime_version,
                            )
                            if (not isinstance(response, dict)
                                    or response.get("agentRuntimeId") != runtime_id
                                    or response.get("agentRuntimeArn") != runtime_arn
                                    or response.get("agentRuntimeVersion") != runtime_version):
                                raise InvalidResponse()
                            binding(
                                service, region, runtime_arn, response.get("roleArn"),
                                resource_version=runtime_version,
                            )
                            detail = response
                        except AWS_ERRORS as error:
                            if not options.ai_production:
                                raise
                            production_issues.append(CollectionIssue(None, "GetAgentRuntime", error_message(error)))
                        if options.ai_production:
                            _collect_agentcore_endpoints(context, result, client, region, runtime_id,
                                                        runtime_arn, detail, check, binding, production_issues)
            except AWS_ERRORS as error:
                result.issues.append(CollectionIssue(None, "IdentityBindings:" + service + ":" + region,
                                                     "Metadata page/time budget exhausted or invalid AWS response" if isinstance(error, InvalidResponse) else error_message(error)))
    result.issues.extend(sorted(production_issues, key=lambda issue: (
        issue.operation, issue.resource_id or "", issue.message,
    )))
    for resource in identities.values():
        resource.data["identity_bindings"].sort(key=identity_binding_sort_key)
