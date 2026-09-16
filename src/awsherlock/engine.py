"""Evaluate normalized resources without AWS clients or reporter dependencies."""

from collections.abc import Iterable
from typing import Protocol

from awsherlock.models import Finding, Resource


class Rule(Protocol):
    """Return findings, or [] for a secure/not-applicable resource.

    Rules inspect normalized facts and must not print or call AWS. Missing facts
    or permissions must not be treated as secure. Failures propagate to the
    caller; an empty finding list alone does not establish scan coverage.
    """

    def evaluate(self, resource: Resource) -> list[Finding]: ...


def evaluate_rules(resources: Iterable[Resource], rules: Iterable[Rule]) -> list[Finding]:
    """Run in resource/rule order. Never turn a failed evaluation into a pass."""
    ordered_rules = tuple(rules)
    findings: list[Finding] = []
    for resource in resources:
        if not isinstance(resource, Resource):
            raise TypeError("Rule engine inputs must be Resource instances")
        for rule in ordered_rules:
            result = rule.evaluate(resource)
            if not isinstance(result, list) or any(not isinstance(item, Finding) for item in result):
                raise TypeError("Rules must return a list of Finding instances")
            findings.extend(result)
    return findings
