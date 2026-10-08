"""Strict shapes at the live/offline boundary prevent truthy strings becoming passes."""

import re
from ipaddress import ip_address, ip_network

from awsherlock.models import Resource
from awsherlock.s3_facts import validate_fact

IAM_STATEMENT = {"effect": str, "conditional": bool, "actions": [str], "resources": [str], "not_actions": bool, "not_resources": bool}
RESOURCE_STATEMENT = {"effect": str, "broad_principal": bool, "conditional": bool, "actions": [str]}
SCHEMAS = {
    ("iam", "attached"): [str], ("iam", "statements"): [IAM_STATEMENT],
    ("iam", "console_mfa"): {"console": bool, "mfa": bool},
    ("iam", "key_age"): {"active": bool, "days": int}, ("iam", "key_stale"): {"days": int, "never_used": bool},
    ("ec2", "metadata"): {"endpoint": str, "tokens": str}, ("ec2", "addresses"): [str], ("ec2", "encrypted"): bool,
    ("lambda", "urls"): [{"arn": str, "auth": str}], ("lambda", "role_policies"): [str],
    ("lambda", "runtime"): {"name": str, "deprecated": bool, "catalog_date": str, "evaluated_on": str},
    ("secretsmanager", "rotation"): bool, ("secretsmanager", "policy"): [RESOURCE_STATEMENT],
    ("secretsmanager", "encryption"): {"manager": str, "state": str},
    ("cloudtrail", "usable_trail"): bool,
    ("cloudtrail", "management_events"): bool,
    ("cloudtrail", "management_excluded_sources"): [str],
    ("cloudtrail", "management_event_types"): {"read": bool, "write": bool},
    ("cloudtrail", "trail_settings"): {"IsMultiRegionTrail": bool, "IncludeGlobalServiceEvents": bool, "LogFileValidationEnabled": bool, "IsOrganizationTrail": bool},
    ("cloudtrail", "trail_status"): {"logging": bool, "destination": str, "delivery_error": bool},
    ("kms", "policy"): [RESOURCE_STATEMENT],
    ("rds", "restore_public"): bool,
    ("rds", "storage_encrypted"): bool,
    ("rds", "publicly_accessible"): bool,
    ("guardduty", "enabled_detector_present"): bool,
    ("dynamodb", "pitr_enabled"): bool,
}

_BEDROCK_AGENT_STATUSES = {
    "CREATING", "PREPARING", "PREPARED", "NOT_PREPARED",
    "DELETING", "FAILED", "VERSIONING", "UPDATING",
}
_BEDROCK_DESTINATIONS = {"cloudwatch", "s3"}
_BEDROCK_MODALITIES = {"audio", "embedding", "image", "text", "video"}


def _bedrock_fact(resource: Resource, fact: str, value: object) -> None:
    if resource.resource_type == "agent":
        if fact == "agent_status":
            if value not in _BEDROCK_AGENT_STATUSES:
                raise ValueError("Invalid Bedrock Agent status")
            return
        if fact == "agent_version":
            if value != "DRAFT":
                raise ValueError("Invalid Bedrock Agent version")
            return
        if fact == "execution_role_arn":
            if not isinstance(value, str) or re.fullmatch(
                rf"arn:[a-z0-9-]+:iam::{resource.account_id}:role/[^\s*?]+", value,
            ) is None:
                raise ValueError("Invalid Bedrock execution role ARN")
            return
        if fact == "guardrail_configuration":
            if not isinstance(value, dict) or set(value) != {"identifier", "version"}:
                raise ValueError("Invalid Bedrock Guardrail configuration")
            identifier, version = value["identifier"], value["version"]
            if identifier is None and version is None:
                return
            if not isinstance(identifier, str) or not isinstance(version, str):
                raise ValueError("Invalid Bedrock Guardrail configuration")
            guardrail_id = identifier.rsplit("/", 1)[-1]
            if re.fullmatch(r"[a-z0-9]+", guardrail_id) is None or re.fullmatch(
                r"(?:[0-9]{1,8}|DRAFT)", version,
            ) is None:
                raise ValueError("Invalid Bedrock Guardrail configuration")
            if identifier != guardrail_id and re.fullmatch(
                rf"arn:[a-z0-9-]+:bedrock:{re.escape(resource.region or '')}:"
                rf"{resource.account_id}:guardrail/{guardrail_id}", identifier,
            ) is None:
                raise ValueError("Invalid Bedrock Guardrail ARN")
            return
    if resource.resource_type == "regional-settings" and fact == "model_invocation_logging_configuration":
        if not isinstance(value, dict) or set(value) != {"configured", "destinations", "modalities"}:
            raise ValueError("Invalid Bedrock Runtime logging configuration")
        configured = value["configured"]
        destinations = value["destinations"]
        modalities = value["modalities"]
        if type(configured) is not bool or not isinstance(destinations, list) or not isinstance(modalities, list):
            raise ValueError("Invalid Bedrock Runtime logging configuration")
        if (destinations != sorted(set(destinations)) or modalities != sorted(set(modalities))
                or not set(destinations) <= _BEDROCK_DESTINATIONS
                or not set(modalities) <= _BEDROCK_MODALITIES
                or not configured and (destinations or modalities)):
            raise ValueError("Inconsistent Bedrock Runtime logging configuration")
        return
    raise ValueError("Invalid Bedrock normalized fact")


def _matches(value, shape) -> bool:
    if isinstance(shape, type):
        return type(value) is shape and (shape is not int or value >= 0)
    if isinstance(shape, list):
        return isinstance(value, list) and all(_matches(item, shape[0]) for item in value)
    return isinstance(value, dict) and set(value) == set(shape) and all(_matches(value[key], child) for key, child in shape.items())


def validate_resource_facts(resource: Resource) -> None:
    if (resource.service == "bedrock" and resource.resource_type == "agent"
            and "guardrail_configuration" in resource.data
            and resource.data.get("agent_version") != "DRAFT"):
        raise ValueError("Bedrock Guardrail evidence requires DRAFT Agent context")
    for fact, value in resource.data.items():
        if resource.service == "bedrock":
            _bedrock_fact(resource, fact, value)
            continue
        if resource.service == "iam" and fact.startswith("identity_"):
            from awsherlock.identity_validation import validate_identity_fact
            validate_identity_fact(fact, value)
            if fact == "identity_bindings" and any(binding["role_arn"] != resource.resource_arn for binding in value):
                raise ValueError("Binding does not match identity")
            continue
        if resource.service == "s3":
            validate_fact(fact, value)
            continue
        if resource.service == "ec2" and fact == "ingress":
            if not isinstance(value, list):
                raise ValueError("Invalid ingress")
            for rule in value:
                if not isinstance(rule, dict) or set(rule) != {"protocol", "from", "to", "cidrs"} or not isinstance(rule["protocol"], str):
                    raise ValueError("Invalid ingress")
                if rule["protocol"] in {"tcp", "udp", "6", "17"}:
                    if type(rule["from"]) is not int or type(rule["to"]) is not int or not 0 <= rule["from"] <= rule["to"] <= 65535:
                        raise ValueError("Invalid port range")
                if not isinstance(rule["cidrs"], list):
                    raise ValueError("Invalid CIDRs")
                for cidr in rule["cidrs"]:
                    if not isinstance(cidr, str):
                        raise ValueError("Invalid CIDR")
                    ip_network(cidr)
            continue
        if resource.service == "kms" and fact == "rotation":
            shape = {"eligible": bool, "enabled": bool} if isinstance(value, dict) and value.get("eligible") is True else {"eligible": bool, "reason": str}
        else:
            shape = SCHEMAS.get((resource.service, fact))
        if shape is None or not _matches(value, shape):
            raise ValueError("Invalid normalized fact shape")
        if resource.service == "cloudtrail" and fact == "management_excluded_sources":
            from awsherlock.cloudtrail_facts import MANAGEMENT_SOURCES
            if not set(value) <= MANAGEMENT_SOURCES:
                raise ValueError("Invalid management source exclusions")
        if fact in {"statements", "policy"}:
            if any(s["effect"] not in {"Allow", "Deny"} or not s["actions"] for s in value):
                raise ValueError("Invalid policy facts")
        if resource.service == "ec2" and fact == "addresses":
            for address in value:
                ip_address(address)
        if resource.service == "ec2" and fact == "metadata":
            if value["endpoint"] not in {"enabled", "disabled"} or value["tokens"] not in {"optional", "required"}:
                raise ValueError("Invalid metadata options")
        if resource.service == "lambda" and fact == "urls" and any(url["auth"] not in {"NONE", "AWS_IAM"} for url in value):
            raise ValueError("Invalid URL authentication")
    if resource.service == "cloudtrail" and "management_events" in resource.data and "management_event_types" in resource.data:
        if resource.data["management_events"] != any(resource.data["management_event_types"].values()):
            raise ValueError("Inconsistent management event selector facts")
