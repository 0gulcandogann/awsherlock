"""Regional Lambda metadata, no function code or environment values exported."""

from datetime import date
from botocore.exceptions import ClientError
from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import AWS_ERRORS, CollectionIssue, CollectionResult, InvalidResponse, collect_fact, error_message, items, text_field
from awsherlock.models import Resource
from awsherlock.runtime_catalog import runtime_fact


def collect_lambda(context: ScanContext, *, today: date | None = None) -> CollectionResult:
    result = CollectionResult()
    if context.region is None:
        result.issues.append(CollectionIssue(None, "Region", "Configure an AWS region for Lambda"))
        return result
    roles = {}
    today = today or date.today()
    try:
        client = context.session.client("lambda", region_name=context.region)
        for page in client.get_paginator("list_functions").paginate():
            for function in items(page, "Functions"):
                name = None
                try:
                    if not isinstance(function, dict):
                        raise InvalidResponse()
                    name = text_field(function.get("FunctionName"))
                    arn = text_field(function.get("FunctionArn"))
                    resource = Resource(service="lambda", resource_type="function", account_id=context.account_id,
                                        region=context.region, resource_id=name, resource_arn=arn)
                    result.resources.append(resource)
                    def runtime():
                        package = function.get("PackageType")
                        if package == "Image":
                            # Container runtime inventory requires inspecting images, out of scope.
                            raise InvalidResponse()
                        if package not in {None, "Zip"}:
                            raise InvalidResponse()
                        return runtime_fact(text_field(function.get("Runtime")), today)
                    collect_fact(result, resource, "runtime", "ManagedRuntime (images/unknown runtimes not scanned)", runtime)
                    def urls():
                        auth = []
                        # Lists URLs for all aliases as well as the unqualified function.
                        for url_page in client.get_paginator("list_function_url_configs").paginate(FunctionName=name):
                            for config in items(url_page, "FunctionUrlConfigs"):
                                if not isinstance(config, dict) or config.get("AuthType") not in {"NONE", "AWS_IAM"}:
                                    raise InvalidResponse()
                                auth.append({"arn": text_field(config.get("FunctionArn")), "auth": config["AuthType"]})
                        return auth
                    collect_fact(result, resource, "urls", "ListFunctionUrlConfigs", urls)
                    def role_policies():
                        role = text_field(function.get("Role"))
                        if role not in roles:
                            role_name = role.rsplit("/", 1)[-1]
                            iam = context.session.client("iam")
                            policies = []
                            for policy_page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
                                for policy in items(policy_page, "AttachedPolicies"):
                                    if not isinstance(policy, dict):
                                        raise InvalidResponse()
                                    policies.append(text_field(policy.get("PolicyArn")))
                            roles[role] = policies
                        return roles[role]
                    collect_fact(result, resource, "role_policies", "ListAttachedRolePolicies", role_policies)
                except AWS_ERRORS as error:
                    result.issues.append(CollectionIssue(name, "LambdaMetadata", error_message(error)))
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(None, "ListFunctions", error_message(error)))
    return result
