"""Secrets Manager metadata only; GetSecretValue is never called."""

from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import AWS_ERRORS, CollectionIssue, CollectionResult, InvalidResponse, collect_fact, error_message, items, text_field
from awsherlock.models import Resource
from awsherlock.resource_policy import statements


def collect_secrets(context: ScanContext) -> CollectionResult:
    result = CollectionResult()
    if context.region is None:
        result.issues.append(CollectionIssue(None, "Region", "Configure an AWS region for Secrets Manager"))
        return result
    keys = {}
    try:
        client = context.session.client("secretsmanager", region_name=context.region)
        for page in client.get_paginator("list_secrets").paginate():
            for secret in items(page, "SecretList"):
                name = None
                try:
                    if not isinstance(secret, dict):
                        raise InvalidResponse()
                    name, arn = text_field(secret.get("Name")), text_field(secret.get("ARN"))
                    resource = Resource(service="secretsmanager", resource_type="secret", account_id=context.account_id,
                                        region=context.region, resource_id=name, resource_arn=arn)
                    result.resources.append(resource)
                    def rotation():
                        value = secret.get("RotationEnabled", False)
                        if type(value) is not bool:
                            raise InvalidResponse()
                        return value
                    collect_fact(result, resource, "rotation", "RotationMetadata", rotation)
                    def policy():
                        response = client.get_resource_policy(SecretId=arn)
                        if not isinstance(response, dict):
                            raise InvalidResponse()
                        return statements(response.get("ResourcePolicy"))
                    collect_fact(result, resource, "policy", "GetResourcePolicy", policy)
                    def encryption():
                        key = secret.get("KmsKeyId")
                        if key is None:
                            return {"manager": "AWS", "state": "Enabled"}  # aws/secretsmanager default.
                        key = text_field(key)
                        if key not in keys:
                            kms = context.session.client("kms", region_name=context.region)
                            response = kms.describe_key(KeyId=key)
                            metadata = response.get("KeyMetadata") if isinstance(response, dict) else None
                            if not isinstance(metadata, dict):
                                raise InvalidResponse()
                            state = text_field(metadata.get("KeyState"))
                            keys[key] = {"manager": text_field(metadata.get("KeyManager")), "state": state}
                        return keys[key]
                    collect_fact(result, resource, "encryption", "DescribeKey", encryption)
                except AWS_ERRORS as error:
                    result.issues.append(CollectionIssue(name, "SecretMetadata", error_message(error)))
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(None, "ListSecrets", error_message(error)))
    return result
