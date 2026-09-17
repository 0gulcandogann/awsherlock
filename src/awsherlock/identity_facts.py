"""Allowlisted IAM trust and profile facts; never retain raw policies or tags."""

import json
import re
from datetime import datetime
from urllib.parse import unquote

from awsherlock.collectors.common import InvalidResponse, age_days, text_field


def profile_fact(raw: dict, tags: list, kind: str) -> dict:
    selected = {}
    for tag in tags:
        if not isinstance(tag, dict) or not isinstance(tag.get("Key"), str) or not isinstance(tag.get("Value"), str):
            raise InvalidResponse()
        if tag["Key"] in {"Owner", "Purpose", "IdentityType"}:
            selected[tag["Key"]] = tag["Value"]
    declared = selected.get("IdentityType", "unknown").lower()
    if declared not in {"ai", "workload", "human", "unknown"}:
        declared = "unknown"
    boundary = raw.get("PermissionsBoundary")
    if boundary is not None:
        if not isinstance(boundary, dict):
            raise InvalidResponse()
        boundary = text_field(boundary.get("PermissionsBoundaryArn"))
    return {"owner": bool(selected.get("Owner", "").strip()), "purpose": bool(selected.get("Purpose", "").strip()),
            "declared_kind": declared, "boundary": boundary,
            "service_linked": kind == "role" and raw.get("Path", "").startswith("/aws-service-role/")}


def usage_fact(raw: dict, now: datetime) -> dict:
    created = age_days(raw.get("CreateDate"), now)
    last = raw.get("RoleLastUsed")
    if last is None:
        return {"created_days": created, "last_used_days": None, "status": "unknown"}
    if not isinstance(last, dict):
        raise InvalidResponse()
    date = last.get("LastUsedDate")
    return {"created_days": created, "last_used_days": age_days(date, now) if date is not None else None,
            "status": "recorded" if date is not None else "no_record"}


def trust_fact(document: object) -> dict:
    if isinstance(document, str):
        try:
            document = json.loads(unquote(document))
        except (ValueError, RecursionError):
            raise InvalidResponse() from None
    if not isinstance(document, dict) or "Statement" not in document:
        raise InvalidResponse()
    statements = document["Statement"]
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list):
        raise InvalidResponse()
    principals, mechanisms = [], set()
    broad = False
    unknown = False
    external_controls, source_controls = [], []
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") not in {"Allow", "Deny"}:
            raise InvalidResponse()
        if statement["Effect"] == "Deny":
            # Full deny simulation is deliberately not performed.
            unknown = True
            continue
        actions = statement.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(actions, list) or any(not isinstance(a, str) for a in actions):
            raise InvalidResponse()
        supported = {"sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML", "sts:TagSession", "sts:SetSourceIdentity"}
        if "NotAction" in statement or not actions or not set(actions) <= supported:
            unknown = True
        principal = statement.get("Principal")
        principal = {"AWS": principal} if isinstance(principal, str) else principal
        if not isinstance(principal, dict) or not principal or "NotPrincipal" in statement:
            unknown = True
            continue
        condition = statement.get("Condition", {})
        if not isinstance(condition, dict):
            raise InvalidResponse()
        known_conditions = True
        narrowed = []
        external = source = False
        audience, subject = set(), set()
        federated = principal.get("Federated", [])
        federated = [federated] if isinstance(federated, str) else federated
        issuers = {p.split(":oidc-provider/", 1)[1] for p in federated if isinstance(p, str) and ":oidc-provider/" in p} if isinstance(federated, list) else set()
        for operator, fields in condition.items():
            if not isinstance(fields, dict):
                raise InvalidResponse()
            for key, values in fields.items():
                values = [values] if isinstance(values, str) else values
                if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
                    raise InvalidResponse()
                exact = all("*" not in v and "?" not in v for v in values)
                if operator in {"ArnEquals", "StringEquals"} and key == "aws:PrincipalArn" and exact and all(
                    re.fullmatch(r"arn:[a-z0-9-]+:iam::[0-9]{12}:(?:root|(?:role|user)/[^\s*?]+)", v) for v in values
                ):
                    narrowed.extend(values)
                elif operator == "StringEquals" and key == "aws:PrincipalAccount" and all(re.fullmatch(r"[0-9]{12}", v) for v in values):
                    narrowed.extend(values)
                elif operator == "StringEquals" and key == "sts:ExternalId" and exact:
                    external = True
                elif operator in {"StringEquals", "StringLike"} and key == "sts:SourceIdentity":
                    source = True
                elif operator == "StringEquals" and key.endswith(":aud") and key[:-4] in issuers and exact:
                    audience.add(key[:-4])
                elif operator == "StringEquals" and key.endswith(":sub") and key[:-4] in issuers and exact:
                    subject.add(key[:-4])
                elif operator in {"ArnEquals", "ArnLike"} and key == "aws:SourceArn" and exact:
                    pass
                elif operator == "StringEquals" and key == "aws:SourceAccount" and all(re.fullmatch(r"[0-9]{12}", v) for v in values):
                    pass
                else:
                    known_conditions = False
        if condition and not known_conditions:
            unknown = True
        if any(action in {"sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML"} for action in actions):
            external_controls.append(external)
            source_controls.append(source)
        for principal_kind, values in principal.items():
            values = [values] if isinstance(values, str) else values
            if principal_kind not in {"AWS", "Service", "Federated"} or not isinstance(values, list) or not values:
                unknown = True
                continue
            for value in values:
                value = text_field(value)
                wildcard = "*" in value or "?" in value
                if not wildcard and principal_kind == "AWS" and not re.fullmatch(
                    r"(?:[0-9]{12}|arn:[a-z0-9-]+:iam::[0-9]{12}:(?:root|(?:role|user)/[^\s*?]+))", value
                ):
                    unknown = True
                if wildcard and narrowed and known_conditions and principal_kind == "AWS":
                    principals.extend({"kind": "AWS", "value": p} for p in narrowed)
                else:
                    principals.append({"kind": principal_kind, "value": value})
                    if wildcard:
                        if not condition:
                            broad = True
                        else:
                            unknown = True
            if principal_kind == "AWS":
                mechanisms.add("assume_role")
            elif principal_kind == "Service":
                mechanisms.add("aws_service")
            elif "sts:AssumeRoleWithWebIdentity" in actions:
                mechanisms.add("oidc")
                required_issuers = {value.split(":oidc-provider/", 1)[1] for value in values if ":oidc-provider/" in value}
                if not required_issuers or not required_issuers <= audience & subject:
                    broad = True
            else:
                mechanisms.add("federation")
    unique = {(p["kind"], p["value"]) for p in principals}
    return {"principals": [{"kind": k, "value": v} for k, v in sorted(unique)], "mechanisms": sorted(mechanisms),
            "broad": broad, "status": "unknown" if unknown else "supported",
            "external_id_condition": bool(external_controls) and all(external_controls),
            "source_identity_condition": bool(source_controls) and all(source_controls)}
