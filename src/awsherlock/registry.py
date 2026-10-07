"""Canonical ordered registry for supported services and security checks."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from awsherlock.aws.context import ScanContext
from awsherlock.collectors.cloudtrail import collect_cloudtrail
from awsherlock.collectors.common import CollectionResult
from awsherlock.collectors.dynamodb import collect_dynamodb
from awsherlock.collectors.ec2 import collect_ec2
from awsherlock.collectors.guardduty import collect_guardduty
from awsherlock.collectors.iam import collect_iam
from awsherlock.collectors.kms import collect_kms
from awsherlock.collectors.lambda_service import collect_lambda
from awsherlock.collectors.rds import collect_rds
from awsherlock.collectors.s3 import collect_s3
from awsherlock.collectors.secrets import collect_secrets
from awsherlock.models import Finding, Resource, Severity
from awsherlock.rules.audit import CLOUDTRAIL_RULES, KMS_RULES
from awsherlock.rules.dynamodb import DYNAMODB_RULES
from awsherlock.rules.ec2 import EC2_RULES
from awsherlock.rules.guardduty import GUARDDUTY_RULES
from awsherlock.rules.iam import IAM_RULES
from awsherlock.rules.rds import RDS_RULES
from awsherlock.rules.s3 import S3_RULES
from awsherlock.rules.serverless import LAMBDA_RULES, SECRET_RULES

Collector = Callable[[ScanContext], CollectionResult]


class RegisteredEvaluator(Protocol):
    required_fact: str

    def evaluate(self, resource: Resource) -> list[Finding]: ...


class NumberedEvaluator(RegisteredEvaluator, Protocol):
    number: int


@dataclass(frozen=True, kw_only=True)
class CheckSpec:
    """Discovery metadata paired with the existing runtime evaluator."""

    identifier: str
    title: str
    severity: Severity
    service: str
    required_fact: str
    remediation: str
    references: tuple[str, ...]
    scope_limitations: str
    evaluator: RegisteredEvaluator


@dataclass(frozen=True, kw_only=True)
class ServiceSpec:
    """One supported service, its normalized facts and ordered checks."""

    identifier: str
    check_prefix: str
    scope: str
    default_enabled: bool
    collector: Collector
    resource_facts: Mapping[str, frozenset[str]]
    evaluators: tuple[RegisteredEvaluator, ...]
    checks: tuple[CheckSpec, ...]
    completed_operations: tuple[str, ...] = ()


_SCOPES = {
    "iam": "Global IAM policy indicators and opt-in role/user governance; missing facts and incomplete policy joins appear in coverage issues. Declarations and observed callers are separate evidence; effective permissions are not simulated.",
    "s3": "Bucket configuration with known account Block Public Access context; missing bucket facts appear in coverage issues. Effective anonymous access is not evaluated.",
    "ec2": "Regional configuration; identified resources retain valid facts when another fact is invalid, with missing facts in coverage issues. Routes, NACLs and application controls are not evaluated.",
    "lambda": "Regional function metadata indicators; missing URL, role-policy or runtime facts appear in coverage issues. Function code and environment values are not read.",
    "secretsmanager": "Regional secret metadata indicators; missing rotation, policy or encryption facts appear in coverage issues. Secret values are never read.",
    "cloudtrail": "Regional trail indicators; missing facts appear in coverage issues. CT-004 needs source and read/write context. Full API logging, delivery and retention are unverified.",
    "kms": "Regional key configuration indicators; missing rotation or policy facts appear in coverage issues for discovered keys. AWS-managed key policies are excluded.",
    "rds": "Opt-in regional manual snapshot restore permissions and non-cluster DB instance storage encryption/public-access settings. Findings are configuration indicators; actual data access, internet reachability, key policy and encryption in transit are not verified.",
    "guardduty": "Opt-in regional detector presence and enabled status. Optional protection plans and other Regions are not verified.",
    "dynamodb": "Opt-in regional table point-in-time recovery status. On-demand backups, restore success and other Regions are not verified.",
}

_S3_TITLES = (
    "S3 bucket public access safeguards are incomplete",
    "S3 default encryption configuration needs review",
    "S3 bucket versioning is not enabled",
    "S3 server access logging is disabled",
    "S3 bucket policy is classified as public",
)
_S3_REMEDIATION = (
    "Review intended access and enable all four bucket Block Public Access settings.",
    "Review the default encryption configuration and select SSE-S3, SSE-KMS, or DSSE-KMS.",
    "Enable bucket versioning and review lifecycle retention requirements.",
    "Configure an appropriate server access logging destination.",
    "Review the bucket policy and restrict access to intended principals and conditions.",
)


def _check(identifier: str, service: str, evaluator: RegisteredEvaluator, severity: Severity,
           references: tuple[str, ...], *, title: str | None = None,
           remediation: str | None = None) -> CheckSpec:
    return CheckSpec(
        identifier=identifier,
        title=title if title is not None else getattr(evaluator, "title"),
        severity=severity,
        service=service,
        required_fact=evaluator.required_fact,
        remediation=remediation if remediation is not None else getattr(evaluator, "remediation"),
        references=references,
        scope_limitations=_SCOPES[service],
        evaluator=evaluator,
    )


def _numbered(service: str, prefix: str, rules: tuple[NumberedEvaluator, ...],
              severities: tuple[Severity, ...], reference: str,
              *, remediation: str | None = None) -> tuple[CheckSpec, ...]:
    return tuple(_check(f"AWSH-{prefix}-{rule.number:03}", service, rule, severity,
                        (reference,), remediation=remediation)
                 for rule, severity in zip(rules, severities, strict=True))


_IDENTITY_COMMON = frozenset({
    "identity_requested", "identity_profile", "identity_approval",
    "identity_policy_context", "identity_bindings", "identity_activity",
    "identity_analyzer_findings",
})


def _resource_facts(entries: dict[str, set[str] | frozenset[str]]) -> Mapping[str, frozenset[str]]:
    return MappingProxyType({kind: frozenset(facts) for kind, facts in entries.items()})


_IAM_CHECKS = _numbered(
    "iam", "IAM", IAM_RULES,
    (Severity.HIGH, Severity.MEDIUM, Severity.MEDIUM, Severity.HIGH,
     Severity.MEDIUM, Severity.MEDIUM, Severity.MEDIUM, Severity.MEDIUM,
     Severity.MEDIUM, Severity.HIGH, Severity.MEDIUM, Severity.HIGH),
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
)
_S3_CHECKS = tuple(
    _check(f"AWSH-S3-{index:03}", "s3", rule, severity,
           (("https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
             if index == 1 else
             "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"),),
           title=_S3_TITLES[index - 1], remediation=_S3_REMEDIATION[index - 1])
    for index, (rule, severity) in enumerate(zip(
        S3_RULES,
        (Severity.MEDIUM, Severity.LOW, Severity.MEDIUM, Severity.LOW, Severity.HIGH),
        strict=True,
    ), 1)
)
_EC2_CHECKS = _numbered(
    "ec2", "EC2", EC2_RULES,
    (Severity.HIGH, Severity.HIGH, Severity.HIGH, Severity.MEDIUM,
     Severity.MEDIUM, Severity.HIGH),
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html",
    remediation="Restrict ingress and public addressing; require IMDSv2 and use encrypted EBS volumes as applicable.",
)
_LAMBDA_CHECKS = _numbered(
    "lambda", "LAMBDA", LAMBDA_RULES,
    (Severity.HIGH, Severity.HIGH, Severity.MEDIUM),
    "https://docs.aws.amazon.com/lambda/",
)
_SECRET_CHECKS = _numbered(
    "secretsmanager", "SECRET", SECRET_RULES,
    (Severity.MEDIUM, Severity.MEDIUM, Severity.MEDIUM),
    "https://docs.aws.amazon.com/secretsmanager/",
)
_CLOUDTRAIL_CHECKS = _numbered(
    "cloudtrail", "CT", CLOUDTRAIL_RULES,
    (Severity.HIGH, Severity.MEDIUM, Severity.MEDIUM, Severity.MEDIUM),
    "https://docs.aws.amazon.com/cloudtrail/",
)
_KMS_CHECKS = _numbered(
    "kms", "KMS", KMS_RULES, (Severity.MEDIUM, Severity.MEDIUM),
    "https://docs.aws.amazon.com/kms/",
)
_RDS_CHECKS = (
    _check("AWSH-RDS-001", "rds", RDS_RULES[0], Severity.HIGH, (
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.Public.html",
        "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-share-snapshot.public.html",
    )),
    _check("AWSH-RDS-002", "rds", RDS_RULES[1], Severity.MEDIUM, (
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
    )),
    _check("AWSH-RDS-003", "rds", RDS_RULES[2], Severity.MEDIUM, (
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html",
    )),
)
_GUARDDUTY_CHECKS = (
    _check("AWSH-GD-001", "guardduty", GUARDDUTY_RULES[0], Severity.MEDIUM, (
        "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html",
    )),
)
_DYNAMODB_CHECKS = (
    _check("AWSH-DDB-001", "dynamodb", DYNAMODB_RULES[0], Severity.MEDIUM, (
        "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Point-in-time-recovery.html",
    )),
)

SERVICE_SPECS = (
    ServiceSpec(identifier="iam", check_prefix="IAM", scope=_SCOPES["iam"],
                default_enabled=True, collector=collect_iam,
                resource_facts=_resource_facts({
                    "user": {"attached", "statements", "console_mfa"} | _IDENTITY_COMMON,
                    "role": {"attached", "statements", "identity_trust", "identity_usage"} | _IDENTITY_COMMON,
                    "group": {"attached", "statements"}, "policy": {"statements"},
                    "access_key": {"key_age", "key_stale"},
                }), evaluators=IAM_RULES, checks=_IAM_CHECKS),
    ServiceSpec(identifier="s3", check_prefix="S3", scope=_SCOPES["s3"],
                default_enabled=True, collector=collect_s3,
                resource_facts=_resource_facts({"bucket": {
                    "public_access_block", "account_public_access_block", "encryption",
                    "versioning", "logging", "policy_public",
                }}), evaluators=S3_RULES, checks=_S3_CHECKS),
    ServiceSpec(identifier="ec2", check_prefix="EC2", scope=_SCOPES["ec2"],
                default_enabled=True, collector=collect_ec2,
                resource_facts=_resource_facts({
                    "security-group": {"ingress"}, "instance": {"metadata", "addresses"},
                    "volume": {"encrypted"},
                }), evaluators=EC2_RULES, checks=_EC2_CHECKS),
    ServiceSpec(identifier="lambda", check_prefix="LAMBDA", scope=_SCOPES["lambda"],
                default_enabled=True, collector=collect_lambda,
                resource_facts=_resource_facts({"function": {"urls", "runtime", "role_policies"}}),
                evaluators=LAMBDA_RULES, checks=_LAMBDA_CHECKS),
    ServiceSpec(identifier="secretsmanager", check_prefix="SECRET", scope=_SCOPES["secretsmanager"],
                default_enabled=True, collector=collect_secrets,
                resource_facts=_resource_facts({"secret": {"rotation", "policy", "encryption"}}),
                evaluators=SECRET_RULES, checks=_SECRET_CHECKS),
    ServiceSpec(identifier="cloudtrail", check_prefix="CT", scope=_SCOPES["cloudtrail"],
                default_enabled=True, collector=collect_cloudtrail,
                resource_facts=_resource_facts({
                    "trail": {"trail_settings", "trail_status", "management_events",
                              "management_excluded_sources", "management_event_types"},
                    "regional_summary": {"usable_trail"},
                }), evaluators=CLOUDTRAIL_RULES, checks=_CLOUDTRAIL_CHECKS),
    ServiceSpec(identifier="kms", check_prefix="KMS", scope=_SCOPES["kms"],
                default_enabled=True, collector=collect_kms,
                resource_facts=_resource_facts({"key": {"rotation", "policy"}}),
                evaluators=KMS_RULES, checks=_KMS_CHECKS),
    ServiceSpec(identifier="rds", check_prefix="RDS", scope=_SCOPES["rds"],
                default_enabled=False, collector=collect_rds,
                resource_facts=_resource_facts({
                    "db-snapshot": {"restore_public"},
                    "db-cluster-snapshot": {"restore_public"},
                    "db-instance": {"storage_encrypted", "publicly_accessible"},
                }), evaluators=RDS_RULES, checks=_RDS_CHECKS,
                completed_operations=("DescribeDBInstances",)),
    ServiceSpec(identifier="guardduty", check_prefix="GD", scope=_SCOPES["guardduty"],
                default_enabled=False, collector=collect_guardduty,
                resource_facts=_resource_facts({"regional-summary": {"enabled_detector_present"}}),
                evaluators=GUARDDUTY_RULES, checks=_GUARDDUTY_CHECKS),
    ServiceSpec(identifier="dynamodb", check_prefix="DDB", scope=_SCOPES["dynamodb"],
                default_enabled=False, collector=collect_dynamodb,
                resource_facts=_resource_facts({"table": {"pitr_enabled"}}),
                evaluators=DYNAMODB_RULES, checks=_DYNAMODB_CHECKS),
)

_SERVICE_INDEX = MappingProxyType({spec.identifier: spec for spec in SERVICE_SPECS})
RESOURCE_FACTS = MappingProxyType({
    (service.identifier, resource_type): facts
    for service in SERVICE_SPECS
    for resource_type, facts in service.resource_facts.items()
})


def _validate_registry() -> None:
    if len(_SERVICE_INDEX) != len(SERVICE_SPECS):
        raise ValueError("Duplicate service identifier")
    checks = check_specs()
    if len({spec.identifier for spec in checks}) != len(checks):
        raise ValueError("Duplicate check identifier")
    for service in SERVICE_SPECS:
        if not service.resource_facts or not service.checks:
            raise ValueError("Service registry entries require facts and checks")
        if any(check.service != service.identifier for check in service.checks):
            raise ValueError("Check service does not match registry owner")
        if (len(service.evaluators) != len(service.checks)
                or any(check.evaluator is not evaluator
                       for check, evaluator in zip(service.checks, service.evaluators))):
            raise ValueError("Check evaluator differs from registered evaluator tuple")
        if any(check.required_fact != check.evaluator.required_fact for check in service.checks):
            raise ValueError("Check primary fact differs from evaluator")


def service_spec(identifier: str) -> ServiceSpec:
    return _SERVICE_INDEX[identifier]


def check_specs() -> tuple[CheckSpec, ...]:
    return tuple(check for service in SERVICE_SPECS for check in service.checks)


_validate_registry()
