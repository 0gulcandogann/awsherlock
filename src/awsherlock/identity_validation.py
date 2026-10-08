"""Strict normalized identity evidence at the live/offline boundary."""

import re

PROFILE = {"owner": bool, "purpose": bool, "declared_kind": str, "boundary": (str, type(None)), "service_linked": bool}
APPROVAL = {"status": str, "declared_kind": str, "owner": bool, "purpose": bool, "allowed_principals": [str], "shared": bool}
APPROVAL.update(external_id_required=bool, source_identity_required=bool)
TRUST = {"principals": [{"kind": str, "value": str}], "mechanisms": [str], "broad": bool, "status": str,
         "external_id_condition": bool, "source_identity_condition": bool}
USAGE = {"created_days": int, "last_used_days": (int, type(None)), "status": str}
BINDING = {"service": str, "region": str, "resource_arn": str, "role_arn": str}
VERSIONED_BINDING = {**BINDING, "resource_version": str}
ACTIVITY = {"days": int, "regions": [str], "complete": bool, "events": [
    {"time": str, "region": str, "mechanism": str, "caller_arn": (str, type(None)), "caller_account": (str, type(None)),
     "operation": str, "source_identity_present": bool, "attribution": str, "chain": [str], "chain_complete": bool}]}
ANALYZER = {"analyzer_arn": str, "analyzer_type": str, "region": str, "finding_type": str,
            "status": str, "updated_at": str, "resource_arn": str, "unused_actions": [str],
            "unused_services": [str], "tracking_window_days": (int, type(None))}
ANALYZER["external_principals"] = [str]
SHAPES = {"identity_requested": bool, "identity_profile": PROFILE, "identity_approval": APPROVAL,
          "identity_trust": TRUST, "identity_usage": USAGE,
          "identity_policy_context": {"complete": bool, "managed_sources": [str]},
          "identity_bindings": list, "identity_activity": ACTIVITY, "identity_analyzer_findings": [ANALYZER]}

_AGENTCORE_RUNTIME_ARN = re.compile(
    r"arn:(?P<partition>aws(?:-[a-z0-9-]+)?):bedrock-agentcore:"
    r"(?P<region>[a-z0-9-]+):(?P<account>[0-9]{12}):runtime/"
    r"(?P<runtime_id>[A-Za-z][A-Za-z0-9_]{0,47}-[A-Za-z0-9]{10})"
)
_IAM_ROLE_ARN = re.compile(
    r"arn:(?P<partition>aws(?:-[a-z0-9-]+)?):iam::(?P<account>[0-9]{12}):"
    r"role/(?P<resource>[^\s]+)"
)
_IAM_ROLE_NAME = re.compile(r"[A-Za-z0-9_+=,.@-]{1,64}")
_IAM_ROLE_PATH = re.compile(r"/(?:[\x21-\x7e]+/)?")
_AGENTCORE_RUNTIME_VERSION = re.compile(r"[1-9][0-9]{0,4}")
_BINDING_SERVICE_ORDER = {"lambda": 0, "ec2": 1, "bedrock": 2, "agentcore": 3}


def matches(value, shape) -> bool:
    if isinstance(shape, tuple):
        return any(matches(value, child) for child in shape)
    if isinstance(shape, type):
        return type(value) is shape and (shape is not int or value >= 0)
    if isinstance(shape, list):
        return isinstance(value, list) and all(matches(item, shape[0]) for item in value)
    return isinstance(value, dict) and set(value) == set(shape) and all(matches(value[key], child) for key, child in shape.items())


def agentcore_runtime_arn_identity(value: object) -> tuple[str, str, str, str] | None:
    match = _AGENTCORE_RUNTIME_ARN.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return None
    return match["partition"], match["region"], match["account"], match["runtime_id"]


def is_agentcore_runtime_version(value: object) -> bool:
    return isinstance(value, str) and _AGENTCORE_RUNTIME_VERSION.fullmatch(value) is not None


def _iam_role_arn_identity(value: object) -> tuple[str, str, str] | None:
    match = _IAM_ROLE_ARN.fullmatch(value) if isinstance(value, str) else None
    if match is None or match["resource"].startswith("/"):
        return None
    path_part, separator, role_name = match["resource"].rpartition("/")
    path = f"/{path_part}/" if separator else "/"
    if (
        _IAM_ROLE_NAME.fullmatch(role_name) is None
        or len(path) > 512
        or _IAM_ROLE_PATH.fullmatch(path) is None
    ):
        return None
    return match["partition"], match["account"], role_name


def agentcore_binding_identity(
    binding: object,
) -> tuple[str, str, str, str, str, str] | None:
    if not matches(binding, VERSIONED_BINDING) or binding["service"] != "agentcore":
        return None
    runtime = agentcore_runtime_arn_identity(binding["resource_arn"])
    role = _iam_role_arn_identity(binding["role_arn"])
    version = binding["resource_version"]
    if (
        runtime is None
        or role is None
        or not binding["region"].strip()
        or runtime[1] != binding["region"]
        or role[0] != runtime[0]
        or role[1] != runtime[2]
        or not is_agentcore_runtime_version(version)
    ):
        return None
    return (*runtime, role[2], version)


def identity_binding_sort_key(binding: dict) -> tuple:
    service = binding["service"]
    return (
        _BINDING_SERVICE_ORDER.get(service, len(_BINDING_SERVICE_ORDER)),
        service,
        binding["region"],
        binding["resource_arn"],
        binding["role_arn"],
        binding.get("resource_version", ""),
    )


def validate_identity_fact(name: str, value) -> None:
    if name not in SHAPES or not matches(value, SHAPES[name]):
        raise ValueError("Invalid normalized identity evidence")
    if name == "identity_requested" and value is not True:
        raise ValueError("Invalid identity request marker")
    if name in {"identity_profile", "identity_approval"} and value["declared_kind"] not in {"ai", "workload", "human", "unknown"}:
        raise ValueError("Invalid identity kind")
    if name == "identity_approval" and value["status"] not in {"registered", "unregistered", "unknown"}:
        raise ValueError("Invalid approval status")
    if name == "identity_trust":
        if value["status"] not in {"supported", "unknown"} or any(p["kind"] not in {"AWS", "Service", "Federated"} for p in value["principals"]):
            raise ValueError("Invalid trust evidence")
        if not set(value["mechanisms"]) <= {"assume_role", "aws_service", "oidc", "federation"}:
            raise ValueError("Invalid trust mechanism")
    if name == "identity_usage":
        if value["status"] not in {"unknown", "recorded", "no_record"} or (value["status"] == "recorded") != (value["last_used_days"] is not None):
            raise ValueError("Invalid usage evidence")
    if name == "identity_activity":
        if not 1 <= value["days"] <= 90:
            raise ValueError("Invalid audit window")
        for event in value["events"]:
            if event["mechanism"] not in {"iam_user", "assume_role", "oidc", "federation", "aws_service", "human_session", "unknown"}:
                raise ValueError("Invalid observed mechanism")
            if event["attribution"] not in {"caller_observed", "caller_account_observed", "issuer_only", "unknown"}:
                raise ValueError("Invalid audit attribution")
            if event["caller_account"] is not None and not re.fullmatch(r"[0-9]{12}", event["caller_account"]):
                raise ValueError("Invalid audit account")
    if name == "identity_bindings":
        for binding in value:
            if matches(binding, BINDING):
                if binding["service"] not in {"lambda", "ec2", "bedrock", "agentcore"}:
                    raise ValueError("Invalid workload binding service")
                continue
            if agentcore_binding_identity(binding) is None:
                raise ValueError("Invalid normalized identity evidence")
