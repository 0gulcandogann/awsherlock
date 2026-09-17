"""Strict normalized identity evidence at the live/offline boundary."""

import re

PROFILE = {"owner": bool, "purpose": bool, "declared_kind": str, "boundary": (str, type(None)), "service_linked": bool}
APPROVAL = {"status": str, "declared_kind": str, "owner": bool, "purpose": bool, "allowed_principals": [str], "shared": bool}
APPROVAL.update(external_id_required=bool, source_identity_required=bool)
TRUST = {"principals": [{"kind": str, "value": str}], "mechanisms": [str], "broad": bool, "status": str,
         "external_id_condition": bool, "source_identity_condition": bool}
USAGE = {"created_days": int, "last_used_days": (int, type(None)), "status": str}
BINDING = {"service": str, "region": str, "resource_arn": str, "role_arn": str}
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
          "identity_bindings": [BINDING], "identity_activity": ACTIVITY, "identity_analyzer_findings": [ANALYZER]}


def matches(value, shape) -> bool:
    if isinstance(shape, tuple):
        return any(matches(value, child) for child in shape)
    if isinstance(shape, type):
        return type(value) is shape and (shape is not int or value >= 0)
    if isinstance(shape, list):
        return isinstance(value, list) and all(matches(item, shape[0]) for item in value)
    return isinstance(value, dict) and set(value) == set(shape) and all(matches(value[key], child) for key, child in shape.items())


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
    if name == "identity_bindings" and any(binding["service"] not in {"lambda", "ec2", "bedrock", "agentcore"} for binding in value):
        raise ValueError("Invalid workload binding service")
