"""Validate the small S3 fact vocabulary shared by collector and rules."""

from awsherlock.models import JSONValue

PUBLIC_ACCESS_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def validate_fact(name: str, value: JSONValue) -> None:
    """None means confirmed absence, never an API error or an omitted fact."""
    valid = False
    if name in {"public_access_block", "account_public_access_block"}:
        valid = value is None or (isinstance(value, dict) and all(type(value.get(key)) is bool for key in PUBLIC_ACCESS_FLAGS))
    elif name == "encryption":
        valid = value is None or (
            isinstance(value, list) and bool(value)
            and all(isinstance(algorithm, str) and bool(algorithm.strip()) for algorithm in value)
        )
    elif name == "versioning":
        valid = value is None or (isinstance(value, str) and value in {"Enabled", "Suspended"})
    elif name == "logging":
        valid = value is None or (isinstance(value, dict) and isinstance(value.get("TargetBucket"), str)
                                 and bool(value["TargetBucket"].strip()) and isinstance(value.get("TargetPrefix"), str))
    elif name == "policy_public":
        valid = value is None or type(value) is bool
    if not valid:
        raise ValueError("Invalid normalized S3 fact")
