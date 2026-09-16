"""Read-only descriptions of the registered security checks."""

from awsherlock.scanner import SERVICES, service_components

_PREFIXES = {"cloudtrail": "CT", "secretsmanager": "SECRET"}
_S3_TITLES = {
    "public_access_block": "S3 bucket public access safeguards are incomplete",
    "encryption": "S3 default encryption configuration needs review",
    "versioning": "S3 bucket versioning is not enabled",
    "logging": "S3 server access logging is disabled",
    "policy_public": "S3 bucket policy is classified as public",
}


def check_catalog() -> list[tuple[str, str, str]]:
    """Return check ID, service and title without collecting or evaluating."""
    checks = []
    for service in SERVICES:
        _, rules = service_components(service)
        prefix = _PREFIXES.get(service, service.upper())
        for index, rule in enumerate(rules, 1):
            number = index if service == "s3" else rule.number
            title = _S3_TITLES[rule.required_fact] if service == "s3" else rule.title
            checks.append((f"AWSH-{prefix}-{number:03}", service, title))
    return checks
