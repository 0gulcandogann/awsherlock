"""Explicit service dispatch; collectors share the authenticated context."""

from awsherlock.collectors.s3 import collect_s3
from awsherlock.collectors.iam import collect_iam
from awsherlock.collectors.ec2 import collect_ec2
from awsherlock.collectors.lambda_service import collect_lambda
from awsherlock.collectors.secrets import collect_secrets
from awsherlock.collectors.cloudtrail import collect_cloudtrail
from awsherlock.collectors.kms import collect_kms
from awsherlock.rules.s3 import S3_RULES
from awsherlock.rules.iam import IAM_RULES
from awsherlock.rules.ec2 import EC2_RULES
from awsherlock.rules.serverless import LAMBDA_RULES, SECRET_RULES
from awsherlock.rules.audit import CLOUDTRAIL_RULES, KMS_RULES

SERVICES = ("iam", "s3", "ec2", "lambda", "secretsmanager", "cloudtrail", "kms")


def service_components(service: str):
    return {"s3": (collect_s3, S3_RULES), "iam": (collect_iam, IAM_RULES), "ec2": (collect_ec2, EC2_RULES),
            "lambda": (collect_lambda, LAMBDA_RULES), "secretsmanager": (collect_secrets, SECRET_RULES),
            "cloudtrail": (collect_cloudtrail, CLOUDTRAIL_RULES), "kms": (collect_kms, KMS_RULES)}[service]


def parse_services(value: str | None) -> list[str]:
    selected = list(SERVICES) if value is None else list(dict.fromkeys(part.strip() for part in value.split(",")))
    if any(service not in SERVICES for service in selected):
        raise ValueError("Unsupported service selection")
    return selected
