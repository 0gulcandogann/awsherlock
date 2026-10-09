"""Canonical service/check registry contracts."""

from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
from types import MappingProxyType

import pytest

from awsherlock.collectors.common import CollectionResult
from awsherlock.models import Resource, ScanMetadata, Severity
from awsherlock.registry import (
    RESOURCE_FACTS, SERVICE_SPECS, CheckSpec, ServiceSpec, check_specs, service_spec,
)


EXPECTED_SERVICES = (
    "iam", "s3", "ec2", "lambda", "secretsmanager", "cloudtrail", "kms",
    "rds", "guardduty", "dynamodb", "bedrock",
)
EXPECTED_COUNTS = (12, 5, 6, 3, 3, 4, 2, 3, 1, 1, 2)
EXPECTED_IDS = (
    *(f"AWSH-IAM-{number:03}" for number in range(1, 13)),
    *(f"AWSH-S3-{number:03}" for number in range(1, 6)),
    *(f"AWSH-EC2-{number:03}" for number in range(1, 7)),
    *(f"AWSH-LAMBDA-{number:03}" for number in range(1, 4)),
    *(f"AWSH-SECRET-{number:03}" for number in range(1, 4)),
    *(f"AWSH-CT-{number:03}" for number in range(1, 5)),
    *(f"AWSH-KMS-{number:03}" for number in range(1, 3)),
    *(f"AWSH-RDS-{number:03}" for number in range(1, 4)),
    "AWSH-GD-001", "AWSH-DDB-001", "AWSH-BEDROCK-001", "AWSH-BEDROCK-002",
)


def test_registry_preserves_service_and_check_discovery_contract() -> None:
    assert isinstance(SERVICE_SPECS, tuple)
    assert all(isinstance(spec, ServiceSpec) for spec in SERVICE_SPECS)
    assert tuple(spec.identifier for spec in SERVICE_SPECS) == EXPECTED_SERVICES
    assert tuple(len(spec.checks) for spec in SERVICE_SPECS) == EXPECTED_COUNTS
    assert tuple(spec.identifier for spec in SERVICE_SPECS if spec.default_enabled) == EXPECTED_SERVICES[:7]
    assert tuple(spec.identifier for spec in check_specs()) == EXPECTED_IDS
    assert all(isinstance(spec, CheckSpec) for spec in check_specs())


def test_registry_is_immutable_and_lookup_is_explicit() -> None:
    iam = service_spec("iam")
    assert iam is SERVICE_SPECS[0]
    with pytest.raises(KeyError):
        service_spec("unknown")
    with pytest.raises(FrozenInstanceError):
        iam.default_enabled = False
    with pytest.raises(TypeError):
        iam.resource_facts["role"] = frozenset()


def test_every_registered_evaluator_is_immutable() -> None:
    for check in check_specs():
        with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
            check.evaluator.required_fact = "MUTATED"
        assert check.evaluator.required_fact == check.required_fact


def test_s3_evaluators_are_immutable() -> None:
    for check in service_spec("s3").checks:
        assert {field.name for field in fields(check.evaluator)} == {"required_fact"}
        with pytest.raises(FrozenInstanceError):
            check.evaluator.required_fact = "MUTATED"


def test_registry_owns_primary_fact_catalog_metadata_and_rds_marker() -> None:
    catalog = {spec.identifier: spec for spec in check_specs()}
    assert catalog["AWSH-CT-004"].required_fact == "management_events"
    assert catalog["AWSH-CT-004"].title == "CloudTrail management-event logging is incomplete"
    assert catalog["AWSH-CT-004"].severity is Severity.MEDIUM
    assert catalog["AWSH-IAM-012"].required_fact == "identity_approval"
    assert catalog["AWSH-IAM-012"].severity is Severity.HIGH
    assert catalog["AWSH-S3-002"].severity is Severity.LOW
    assert catalog["AWSH-RDS-001"].references == (
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.Public.html",
        "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-share-snapshot.public.html",
    )
    assert service_spec("rds").completed_operations == ("DescribeDBInstances",)
    assert service_spec("bedrock").completed_operations == ("ListAgents",)
    assert all(not spec.completed_operations for spec in SERVICE_SPECS
               if spec.identifier not in {"rds", "bedrock"})


def test_registry_evaluator_primary_metadata_stays_in_parity() -> None:
    for spec in check_specs():
        assert spec.required_fact == spec.evaluator.required_fact
        if hasattr(spec.evaluator, "title"):
            assert spec.title == spec.evaluator.title
        if hasattr(spec.evaluator, "remediation"):
            assert spec.remediation == spec.evaluator.remediation
        assert spec.references
        assert spec.scope_limitations


def test_scanner_facade_delegates_components_to_registry(monkeypatch) -> None:
    from awsherlock import scanner

    expected = service_spec("s3")
    monkeypatch.setattr(scanner, "service_spec", lambda identifier: expected)
    collector, rules = scanner.service_components("synthetic")
    assert scanner.SERVICE_SPECS is SERVICE_SPECS
    assert collector is expected.collector
    assert rules is expected.evaluators


def test_scanner_preserves_legacy_collector_and_rule_exports() -> None:
    from awsherlock import scanner
    from awsherlock.rules.audit import CLOUDTRAIL_RULES, KMS_RULES
    from awsherlock.rules.dynamodb import DYNAMODB_RULES
    from awsherlock.rules.ec2 import EC2_RULES
    from awsherlock.rules.guardduty import GUARDDUTY_RULES
    from awsherlock.rules.iam import IAM_RULES
    from awsherlock.rules.rds import RDS_RULES
    from awsherlock.rules.s3 import S3_RULES
    from awsherlock.rules.serverless import LAMBDA_RULES, SECRET_RULES

    exports = {
        "iam": ("collect_iam", "IAM_RULES", IAM_RULES),
        "s3": ("collect_s3", "S3_RULES", S3_RULES),
        "ec2": ("collect_ec2", "EC2_RULES", EC2_RULES),
        "lambda": ("collect_lambda", "LAMBDA_RULES", LAMBDA_RULES),
        "secretsmanager": ("collect_secrets", "SECRET_RULES", SECRET_RULES),
        "cloudtrail": ("collect_cloudtrail", "CLOUDTRAIL_RULES", CLOUDTRAIL_RULES),
        "kms": ("collect_kms", "KMS_RULES", KMS_RULES),
        "rds": ("collect_rds", "RDS_RULES", RDS_RULES),
        "guardduty": ("collect_guardduty", "GUARDDUTY_RULES", GUARDDUTY_RULES),
        "dynamodb": ("collect_dynamodb", "DYNAMODB_RULES", DYNAMODB_RULES),
    }
    for service, (collector_name, rules_name, original_rules) in exports.items():
        spec = service_spec(service)
        assert getattr(scanner, collector_name) is spec.collector
        assert spec.evaluators is original_rules
        assert getattr(scanner, rules_name) is original_rules
        assert scanner.service_components(service)[1] is original_rules


def test_duplicate_service_and_check_ids_fail_loudly(monkeypatch) -> None:
    import awsherlock.registry as registry

    iam = service_spec("iam")
    monkeypatch.setattr(registry, "SERVICE_SPECS", (iam, iam))
    monkeypatch.setattr(registry, "_SERVICE_INDEX",
                        MappingProxyType({iam.identifier: iam}))
    with pytest.raises(ValueError, match="Duplicate service identifier"):
        registry._validate_registry()

    duplicate_check_service = replace(iam, checks=(iam.checks[0], iam.checks[0]))
    monkeypatch.setattr(registry, "SERVICE_SPECS", (duplicate_check_service,))
    monkeypatch.setattr(registry, "_SERVICE_INDEX",
                        MappingProxyType({iam.identifier: duplicate_check_service}))
    with pytest.raises(ValueError, match="Duplicate check identifier"):
        registry._validate_registry()


def test_catalog_projects_registry_metadata(monkeypatch) -> None:
    from awsherlock import catalog

    original = check_specs()[0]
    synthetic = replace(original, identifier="AWSH-TEST-001", service="test",
                        title="Synthetic registry title")
    monkeypatch.setattr(catalog, "check_specs", lambda: (synthetic,))
    assert catalog.check_catalog() == [
        ("AWSH-TEST-001", "test", "Synthetic registry title"),
    ]
    assert catalog.describe_check("awsh-test-001") == {
        "Check": "AWSH-TEST-001",
        "Title": "Synthetic registry title",
        "Service": "test",
        "Required fact": synthetic.required_fact,
        "Remediation": synthetic.remediation,
        "Scope": synthetic.scope_limitations,
    }


def test_snapshot_fact_allowlist_is_registry_projection() -> None:
    from awsherlock import snapshot

    assert snapshot.FACTS is RESOURCE_FACTS
    assert snapshot.CURRENT_SCHEMA_VERSION == 2
    assert snapshot.SUPPORTED_SCHEMA_VERSIONS == frozenset({1, 2})


def test_snapshot_unknown_service_preserves_safe_validation_error() -> None:
    from awsherlock.snapshot import Snapshot, SnapshotError

    metadata = ScanMetadata(scan_id="registry-test",
                            started_at=datetime(2026, 10, 7, tzinfo=timezone.utc),
                            account_id="123456789012", region="eu-west-1", version="test")
    with pytest.raises(SnapshotError, match="Invalid normalized snapshot data"):
        Snapshot(metadata, {"unknown": CollectionResult()}).to_dict()


def test_evaluation_consumes_registry_check_specs(monkeypatch) -> None:
    from awsherlock import evaluation
    from awsherlock.snapshot import Snapshot

    metadata = ScanMetadata(scan_id="registry-test",
                            started_at=datetime(2026, 10, 7, tzinfo=timezone.utc),
                            account_id="123456789012", region="eu-west-1", version="test")
    resource = Resource(service="ec2", resource_type="volume",
                        account_id=metadata.account_id, region=metadata.region,
                        resource_id="vol-test", resource_arn=None,
                        data={"encrypted": False})
    original = service_spec("ec2")
    monkeypatch.setattr(evaluation, "service_spec",
                        lambda identifier: replace(original, checks=()))
    report = evaluation.evaluate_snapshot(
        Snapshot(metadata, {"ec2": CollectionResult([resource], [])})
    )
    assert report.findings == []
    assert report.coverage[0]["evaluated"] == 0


def _resource(resource_type: str, data: dict, *, service: str) -> Resource:
    return Resource(service=service, resource_type=resource_type,
                    account_id="123456789012", region=None if service == "iam" else "eu-west-1",
                    resource_id="registry-parity", resource_arn=None, data=data)


def _runtime_parity_resources() -> dict[str, Resource]:
    statement = {"effect": "Allow", "conditional": False, "actions": ["*"],
                 "resources": ["*"], "not_actions": False, "not_resources": False}
    profile = {"owner": False, "purpose": False, "declared_kind": "unknown",
               "boundary": None, "service_linked": False}
    approval = {"status": "unregistered", "declared_kind": "unknown",
                "owner": False, "purpose": False, "allowed_principals": [],
                "shared": False, "external_id_required": False,
                "source_identity_required": False}
    trust = {"principals": [{"kind": "AWS", "value": "*"}],
             "mechanisms": ["assume_role"], "broad": True, "status": "supported",
             "external_id_condition": False, "source_identity_condition": False}
    cases = {
        "AWSH-IAM-001": _resource("role", {"attached": ["arn:aws:iam::aws:policy/AdministratorAccess"]}, service="iam"),
        "AWSH-IAM-002": _resource("role", {"statements": [statement]}, service="iam"),
        "AWSH-IAM-003": _resource("role", {"statements": [statement]}, service="iam"),
        "AWSH-IAM-004": _resource("user", {"console_mfa": {"console": True, "mfa": False}}, service="iam"),
        "AWSH-IAM-005": _resource("access_key", {"key_age": {"active": True, "days": 91}}, service="iam"),
        "AWSH-IAM-006": _resource("access_key", {"key_stale": {"days": 91, "never_used": False}}, service="iam"),
        "AWSH-IAM-007": _resource("role", {"identity_profile": profile, "identity_approval": approval}, service="iam"),
        "AWSH-IAM-008": _resource("role", {"identity_profile": profile, "identity_approval": approval}, service="iam"),
        "AWSH-IAM-009": _resource("role", {"identity_profile": profile, "identity_usage": {
            "created_days": 120, "last_used_days": 91, "status": "recorded"}}, service="iam"),
        "AWSH-IAM-010": _resource("role", {"identity_trust": trust}, service="iam"),
        "AWSH-IAM-011": _resource("role", {"identity_approval": approval}, service="iam"),
        "AWSH-IAM-012": _resource("role", {"identity_approval": {**approval, "status": "registered"},
                                             "identity_trust": trust}, service="iam"),
    }
    s3 = _resource("bucket", {
        "public_access_block": None, "encryption": None, "versioning": None,
        "logging": None, "policy_public": True,
    }, service="s3")
    cases.update({f"AWSH-S3-{number:03}": s3 for number in range(1, 6)})
    group = _resource("security-group", {"ingress": [{
        "protocol": "-1", "from": None, "to": None, "cidrs": ["0.0.0.0/0"],
    }]}, service="ec2")
    instance = _resource("instance", {
        "metadata": {"endpoint": "enabled", "tokens": "optional"},
        "addresses": ["203.0.113.10"],
    }, service="ec2")
    cases.update({"AWSH-EC2-001": group, "AWSH-EC2-002": group, "AWSH-EC2-003": group,
                  "AWSH-EC2-004": instance, "AWSH-EC2-005": instance,
                  "AWSH-EC2-006": _resource("volume", {"encrypted": False}, service="ec2")})
    function = _resource("function", {
        "urls": [{"arn": "arn:aws:lambda:eu-west-1:123456789012:function:test", "auth": "NONE"}],
        "role_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
        "runtime": {"name": "python3.8", "deprecated": True,
                    "catalog_date": "2026-09-15", "evaluated_on": "2026-10-07"},
    }, service="lambda")
    cases.update({f"AWSH-LAMBDA-{number:03}": function for number in range(1, 4)})
    secret = _resource("secret", {
        "rotation": False,
        "policy": [{"effect": "Allow", "broad_principal": True,
                    "conditional": False, "actions": ["secretsmanager:GetSecretValue"]}],
        "encryption": {"manager": "CUSTOMER", "state": "Disabled"},
    }, service="secretsmanager")
    cases.update({f"AWSH-SECRET-{number:03}": secret for number in range(1, 4)})
    cases["AWSH-CT-001"] = _resource("regional_summary", {"usable_trail": False}, service="cloudtrail")
    trail = _resource("trail", {"trail_settings": {
        "IsMultiRegionTrail": False, "IncludeGlobalServiceEvents": False,
        "LogFileValidationEnabled": False, "IsOrganizationTrail": False,
    }, "management_events": False}, service="cloudtrail")
    cases.update({"AWSH-CT-002": trail, "AWSH-CT-003": trail, "AWSH-CT-004": trail})
    cases["AWSH-KMS-001"] = _resource("key", {"rotation": {
        "eligible": True, "enabled": False}}, service="kms")
    cases["AWSH-KMS-002"] = _resource("key", {"policy": [{
        "effect": "Allow", "broad_principal": True, "conditional": False,
        "actions": ["kms:Decrypt"],
    }]}, service="kms")
    cases["AWSH-RDS-001"] = _resource("db-snapshot", {"restore_public": True}, service="rds")
    rds_instance = _resource("db-instance", {
        "storage_encrypted": False, "publicly_accessible": True,
    }, service="rds")
    cases.update({"AWSH-RDS-002": rds_instance, "AWSH-RDS-003": rds_instance})
    cases["AWSH-GD-001"] = _resource("regional-summary", {
        "enabled_detector_present": False}, service="guardduty")
    cases["AWSH-DDB-001"] = _resource("table", {"pitr_enabled": False}, service="dynamodb")
    cases["AWSH-BEDROCK-001"] = _resource(
        "agent",
        {
            "agent_version": "DRAFT",
            "guardrail_configuration": {"identifier": None, "version": None},
        },
        service="bedrock",
    )
    cases["AWSH-BEDROCK-002"] = _resource(
        "regional-settings",
        {
            "model_invocation_logging_configuration": {
                "configured": False,
                "destinations": [],
                "modalities": [],
            },
        },
        service="bedrock",
    )
    return cases


def test_registry_metadata_matches_every_runtime_finding() -> None:
    resources = _runtime_parity_resources()
    assert set(resources) == set(EXPECTED_IDS)
    for spec in check_specs():
        findings = spec.evaluator.evaluate(resources[spec.identifier])
        assert len(findings) == 1, spec.identifier
        finding = findings[0]
        assert (finding.id, finding.title, finding.severity, finding.service,
                finding.remediation, tuple(finding.references)) == (
                    spec.identifier, spec.title, spec.severity, spec.service,
                    spec.remediation, spec.references,
                )
