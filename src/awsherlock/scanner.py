"""Backward-compatible service dispatch backed by the canonical registry."""

from awsherlock.registry import SERVICE_SPECS, service_spec

DEFAULT_SERVICES = tuple(spec.identifier for spec in SERVICE_SPECS if spec.default_enabled)
SERVICES = tuple(spec.identifier for spec in SERVICE_SPECS)

# Preserve the module-level names that callers could import before the registry
# became the canonical dispatch source.
collect_iam = service_spec("iam").collector
collect_s3 = service_spec("s3").collector
collect_ec2 = service_spec("ec2").collector
collect_lambda = service_spec("lambda").collector
collect_secrets = service_spec("secretsmanager").collector
collect_cloudtrail = service_spec("cloudtrail").collector
collect_kms = service_spec("kms").collector
collect_rds = service_spec("rds").collector
collect_guardduty = service_spec("guardduty").collector
collect_dynamodb = service_spec("dynamodb").collector

IAM_RULES = service_spec("iam").evaluators
S3_RULES = service_spec("s3").evaluators
EC2_RULES = service_spec("ec2").evaluators
LAMBDA_RULES = service_spec("lambda").evaluators
SECRET_RULES = service_spec("secretsmanager").evaluators
CLOUDTRAIL_RULES = service_spec("cloudtrail").evaluators
KMS_RULES = service_spec("kms").evaluators
RDS_RULES = service_spec("rds").evaluators
GUARDDUTY_RULES = service_spec("guardduty").evaluators
DYNAMODB_RULES = service_spec("dynamodb").evaluators


def service_components(service: str):
    spec = service_spec(service)
    return spec.collector, spec.evaluators


def parse_services(value: str | None) -> list[str]:
    selected = list(DEFAULT_SERVICES) if value is None else list(dict.fromkeys(part.strip() for part in value.split(",")))
    if any(service not in SERVICES for service in selected):
        raise ValueError("Unsupported service selection")
    return selected
