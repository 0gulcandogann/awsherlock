"""Normalize resource policy structure; conditions are recorded, not evaluated."""

import json
from awsherlock.collectors.common import InvalidResponse, text_field


def statements(document: object) -> list[dict]:
    if document is None:
        return []
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except (ValueError, RecursionError):
            raise InvalidResponse() from None
    if not isinstance(document, dict) or "Statement" not in document:
        raise InvalidResponse()
    entries = document["Statement"]
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list):
        raise InvalidResponse()
    output = []
    for statement in entries:
        if not isinstance(statement, dict) or statement.get("Effect") not in {"Allow", "Deny"}:
            raise InvalidResponse()
        if ("Principal" in statement) == ("NotPrincipal" in statement):
            raise InvalidResponse()
        principal = statement.get("Principal", statement.get("NotPrincipal"))
        if isinstance(principal, dict):
            values = []
            for value in principal.values():
                values.extend(value if isinstance(value, list) else [value])
        else:
            values = principal if isinstance(principal, list) else [principal]
        values = [text_field(value) for value in values]
        if not values:
            raise InvalidResponse()
        if ("Action" in statement) == ("NotAction" in statement):
            raise InvalidResponse()
        actions = statement.get("Action", statement.get("NotAction"))
        actions = actions if isinstance(actions, list) else [actions]
        actions = [text_field(value) for value in actions]
        if not actions or ("Condition" in statement and not isinstance(statement["Condition"], dict)):
            raise InvalidResponse()
        output.append({"effect": statement["Effect"], "broad_principal": "NotPrincipal" in statement or "*" in values,
                       "conditional": bool(statement.get("Condition")), "actions": actions})
    return output
