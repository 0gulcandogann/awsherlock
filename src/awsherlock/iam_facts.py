"""Normalize IAM policy syntax without evaluating effective permissions."""

import json
from urllib.parse import unquote

from awsherlock.collectors.common import InvalidResponse, text_field


def policy_statements(document: object) -> list[dict]:
    if isinstance(document, str):
        try:
            document = json.loads(unquote(document))
        except (ValueError, RecursionError):
            raise InvalidResponse() from None
    if not isinstance(document, dict) or "Statement" not in document:
        raise InvalidResponse()
    statements = document["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        raise InvalidResponse()
    result = []
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") not in {"Allow", "Deny"}:
            raise InvalidResponse()
        normalized = {"effect": statement["Effect"], "conditional": "Condition" in statement}
        if "Condition" in statement and not isinstance(statement["Condition"], dict):
            raise InvalidResponse()
        for positive, negative, target in (("Action", "NotAction", "actions"), ("Resource", "NotResource", "resources")):
            if (positive in statement) == (negative in statement):
                raise InvalidResponse()
            values = statement.get(positive, statement.get(negative))
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list) or not values:
                raise InvalidResponse()
            normalized[target] = [text_field(value) for value in values]
            normalized[f"not_{target}"] = negative in statement
        result.append(normalized)
    return result
