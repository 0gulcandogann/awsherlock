"""KMS configuration reads; never retrieve or decrypt key material."""

from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import AWS_ERRORS, CollectionIssue, CollectionResult, InvalidResponse, collect_fact, error_message, items, text_field
from awsherlock.models import Resource
from awsherlock.resource_policy import statements


def collect_kms(context: ScanContext) -> CollectionResult:
    result = CollectionResult()
    if context.region is None:
        result.issues.append(CollectionIssue(None, "Region", "Configure an AWS region for KMS"))
        return result
    try:
        client = context.client("kms", region_name=context.region)
        seen = set()
        for page in client.get_paginator("list_keys").paginate():
            for key in items(page, "Keys"):
                key_id = None
                try:
                    if not isinstance(key, dict):
                        raise InvalidResponse()
                    key_id = text_field(key.get("KeyId"))
                    if key_id in seen:
                        continue
                    seen.add(key_id)
                    response = client.describe_key(KeyId=key_id)
                    metadata = response.get("KeyMetadata") if isinstance(response, dict) else None
                    if not isinstance(metadata, dict) or metadata.get("KeyManager") not in {"AWS", "CUSTOMER"}:
                        raise InvalidResponse()
                    arn = text_field(metadata.get("Arn"))
                    resource = Resource(service="kms", resource_type="key", account_id=context.account_id,
                                        region=context.region, resource_id=key_id, resource_arn=arn)
                    result.resources.append(resource)
                    if metadata["KeyManager"] == "AWS":
                        resource.data["rotation"] = {"eligible": False, "reason": "AWS-managed key"}
                        continue
                    def rotation():
                        spec = text_field(metadata.get("KeySpec"))
                        origin = text_field(metadata.get("Origin"))
                        state = text_field(metadata.get("KeyState"))
                        usage = text_field(metadata.get("KeyUsage"))
                        eligible = spec == "SYMMETRIC_DEFAULT" and origin == "AWS_KMS" and state == "Enabled" and usage == "ENCRYPT_DECRYPT"
                        if not eligible:
                            return {"eligible": False, "reason": "Key type/origin/state is outside automatic rotation scope"}
                        response = client.get_key_rotation_status(KeyId=key_id)
                        if not isinstance(response, dict) or type(response.get("KeyRotationEnabled")) is not bool:
                            raise InvalidResponse()
                        return {"eligible": True, "enabled": response["KeyRotationEnabled"]}
                    collect_fact(result, resource, "rotation", "GetKeyRotationStatus", rotation)
                    def policy():
                        response = client.get_key_policy(KeyId=key_id, PolicyName="default")
                        if not isinstance(response, dict) or not isinstance(response.get("Policy"), str):
                            raise InvalidResponse()
                        return statements(response["Policy"])
                    collect_fact(result, resource, "policy", "GetKeyPolicy", policy)
                except AWS_ERRORS as error:
                    result.issues.append(CollectionIssue(key_id, "DescribeKey", error_message(error)))
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(None, "ListKeys", error_message(error)))
    return result
