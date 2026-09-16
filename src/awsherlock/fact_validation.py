"""Strict shapes at the live/offline boundary prevent truthy strings becoming passes."""

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
    ("cloudtrail", "trail_settings"): {"IsMultiRegionTrail": bool, "IncludeGlobalServiceEvents": bool, "LogFileValidationEnabled": bool, "IsOrganizationTrail": bool},
    ("cloudtrail", "trail_status"): {"logging": bool, "destination": str, "delivery_error": bool},
    ("kms", "policy"): [RESOURCE_STATEMENT],
}


def _matches(value, shape) -> bool:
    if isinstance(shape, type):
        return type(value) is shape and (shape is not int or value >= 0)
    if isinstance(shape, list):
        return isinstance(value, list) and all(_matches(item, shape[0]) for item in value)
    return isinstance(value, dict) and set(value) == set(shape) and all(_matches(value[key], child) for key, child in shape.items())


def validate_resource_facts(resource: Resource) -> None:
    for fact, value in resource.data.items():
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
