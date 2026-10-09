"""Test-only rules exercise the contract without adding production checks."""

from dataclasses import replace
from unittest.mock import Mock

import pytest

from awsherlock.engine import Rule, evaluate_rules
from awsherlock.models import Finding, Resource, Severity


class ExampleRule:
    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != "test":
            return []
        if resource.data["secure"]:
            return []
        return [Finding(
            id="TEST-001", title="Synthetic finding", description="Test-only rule",
            severity=Severity.LOW, service=resource.service, account_id=resource.account_id,
            region=resource.region, resource_id=resource.resource_id,
            resource_arn=resource.resource_arn, evidence={"secure": False},
            risk="Synthetic risk", remediation="Synthetic remediation",
        )]


@pytest.fixture
def resource() -> Resource:
    return Resource(
        service="test", resource_type="example", account_id="123456789012",
        region=None, resource_id="first", resource_arn=None, data={"secure": False},
    )


def test_insecure_resource(resource: Resource, capsys: pytest.CaptureFixture) -> None:
    rule: Rule = ExampleRule()
    result = evaluate_rules([resource], [rule])
    assert len(result) == 1
    assert isinstance(result[0], Finding)
    assert result[0].resource_id == "first"
    assert result[0].evidence == {"secure": False}
    assert capsys.readouterr() == ("", "")


def test_empty_results(resource: Resource) -> None:
    assert evaluate_rules([replace(resource, data={"secure": True})], [ExampleRule()]) == []
    assert evaluate_rules([replace(resource, service="other")], [ExampleRule()]) == []
    assert evaluate_rules([], [ExampleRule()]) == []
    assert evaluate_rules([resource], []) == []


def test_order_and_iterators(resource: Resource) -> None:
    resources = iter([resource, replace(resource, resource_id="second")])
    results = evaluate_rules(resources, iter([ExampleRule(), ExampleRule()]))
    assert [finding.resource_id for finding in results] == ["first", "first", "second", "second"]


def test_missing_facts_fail_visibly(resource: Resource) -> None:
    with pytest.raises(KeyError, match="secure"):
        evaluate_rules([replace(resource, data={})], [ExampleRule()])


def test_permission_failure_is_not_an_empty_result(resource: Resource) -> None:
    rule = Mock()
    rule.evaluate.side_effect = PermissionError("AccessDenied")
    with pytest.raises(PermissionError, match="AccessDenied"):
        evaluate_rules([resource], [rule])


@pytest.mark.parametrize("result", [None, {}, ["finding"], [{"id": "TEST-001"}], ()])
def test_invalid_rule_output(resource: Resource, result: object) -> None:
    rule = Mock()
    rule.evaluate.return_value = result
    with pytest.raises(TypeError, match="list of Finding"):
        evaluate_rules([resource], [rule])


def test_invalid_resource() -> None:
    with pytest.raises(TypeError, match="Resource instances"):
        evaluate_rules([{}], [ExampleRule()])
