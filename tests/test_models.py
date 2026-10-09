"""Validation and serialization of normalized, synthetic scan data."""

import json
from dataclasses import fields, replace
from datetime import datetime, timezone

import pytest

from awsherlock.models import CoverageStatus, Finding, Resource, ScanMetadata, Severity


@pytest.fixture
def finding() -> Finding:
    return Finding(
        id="TEST-001", title="Test finding", description="Synthetic test condition",
        severity=Severity.HIGH, service="test", account_id="123456789012",
        region=None, resource_id="example", resource_arn=None,
        evidence={"enabled": False, "nested": [None, 3, 1.5, {"name": "example"}]},
        risk="Test risk", remediation="Test remediation",
        references=["https://example.com/test"],
    )


def test_finding_serialization(finding: Finding) -> None:
    result = finding.to_dict()
    assert set(result) == {
        "id", "title", "description", "severity", "service", "account_id", "region",
        "resource_id", "resource_arn", "evidence", "risk", "remediation", "references",
    }
    assert result["severity"] == "HIGH"
    assert type(result["severity"]) is str
    assert json.loads(json.dumps(result, allow_nan=False)) == result
    assert result["evidence"] == finding.evidence
    assert result["region"] is None
    result["evidence"]["nested"].append("changed")
    result["references"].append("changed")
    assert "changed" not in finding.evidence["nested"]
    assert "changed" not in finding.references


@pytest.mark.parametrize("field_name", [
    "id", "title", "description", "service", "resource_id", "risk", "remediation",
])
@pytest.mark.parametrize("value", ["", "  ", None, 123])
def test_required_finding_strings(finding: Finding, field_name: str, value: object) -> None:
    with pytest.raises(ValueError, match=field_name):
        replace(finding, **{field_name: value})


@pytest.mark.parametrize("changes", [
    {"account_id": "123"}, {"account_id": 123456789012},
    {"account_id": "123456789012\n"}, {"region": ""}, {"resource_arn": 42},
    {"severity": "HIGH"}, {"severity": "UNKNOWN"}, {"evidence": []},
    {"evidence": {"value": object()}}, {"evidence": {1: "value"}},
    {"evidence": {"nested": [{"bad": float("nan")}] }},
    {"evidence": {"bad": float("inf")}}, {"references": "https://example.com"},
    {"references": [None]}, {"references": [""]},
])
def test_invalid_finding_values(finding: Finding, changes: dict) -> None:
    with pytest.raises(ValueError):
        replace(finding, **changes)


def test_serialization_revalidates_nested_data(finding: Finding) -> None:
    finding.evidence["bad"] = object()
    with pytest.raises(ValueError, match="JSON-compatible"):
        finding.to_dict()


def test_severity_values(finding: Finding) -> None:
    assert {value.value for value in Severity} == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    for severity in Severity:
        assert replace(finding, severity=severity).to_dict()["severity"] == severity.value
    with pytest.raises(ValueError):
        Severity("unknown")


def test_coverage_values() -> None:
    assert {value.value for value in CoverageStatus} == {"PASS", "FAIL", "ERROR", "NOT_SCANNED", "PARTIAL"}
    assert CoverageStatus.ERROR != CoverageStatus.PASS
    with pytest.raises(ValueError):
        CoverageStatus("unknown")


def test_metadata() -> None:
    metadata = ScanMetadata(
        scan_id="synthetic-scan", started_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
        account_id="123456789012", region=None, version="0.1.0-dev",
    )
    for changes in (
        {"scan_id": ""}, {"version": ""}, {"account_id": "bad"}, {"region": 123},
        {"started_at": datetime(2026, 9, 15)}, {"started_at": "2026-09-15"},
    ):
        with pytest.raises(ValueError):
            replace(metadata, **changes)
    assert "session" not in {item.name for item in fields(metadata)}


def test_resource_validation_and_independent_defaults() -> None:
    resource = Resource(
        service="test", resource_type="example", account_id="123456789012",
        region="eu-central-1", resource_id="example", resource_arn=None,
    )
    other = Resource(
        service="test", resource_type="example", account_id="123456789012",
        region=None, resource_id="other", resource_arn=None,
    )
    resource.data["enabled"] = True
    assert other.data == {}
    for changes in (
        {"service": ""}, {"resource_type": ""}, {"resource_id": ""},
        {"resource_arn": ""}, {"account_id": "bad"}, {"region": ""},
        {"data": []}, {"data": {"bad": object()}},
    ):
        with pytest.raises(ValueError):
            replace(resource, **changes)
