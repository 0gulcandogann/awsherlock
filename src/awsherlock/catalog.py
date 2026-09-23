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
_S3_REMEDIATION = {
    "public_access_block": "Review intended access and enable all four bucket Block Public Access settings.",
    "encryption": "Review the default encryption configuration and select SSE-S3, SSE-KMS, or DSSE-KMS.",
    "versioning": "Enable bucket versioning and review lifecycle retention requirements.",
    "logging": "Configure an appropriate server access logging destination.",
    "policy_public": "Review the bucket policy and restrict access to intended principals and conditions.",
}
_EC2_REMEDIATION = "Restrict ingress and public addressing; require IMDSv2 and use encrypted EBS volumes as applicable."
_SCOPES = {
    "iam": "Global IAM policy indicators and opt-in role/user governance; declarations and observed callers are separate evidence. Effective permissions are not simulated.",
    "s3": "Bucket configuration with known account Block Public Access context; missing bucket facts appear in coverage issues. Effective anonymous access is not evaluated.",
    "lambda": "Regional function metadata indicators; missing URL, role-policy or runtime facts appear in coverage issues. Function code and environment values are not read.",
    "secretsmanager": "Regional secret metadata indicators; missing rotation, policy or encryption facts appear in coverage issues. Secret values are never read.",
    "cloudtrail": "Regional trail indicators; missing facts appear in coverage issues. CT-004 needs source and read/write context. Full API logging, delivery and retention are unverified.",
    "kms": "Regional key configuration indicators; missing rotation or policy facts appear in coverage issues for discovered keys. AWS-managed key policies are excluded.",
    "ec2": "Regional configuration; network routes, NACLs and application controls are not evaluated.",
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


def describe_check(check_id: str) -> dict[str, str] | None:
    """Read registered metadata without constructing sample resources or evaluating."""
    requested = check_id.strip().upper()
    catalog = check_catalog()
    for service in SERVICES:
        _, rules = service_components(service)
        entries = [entry for entry in catalog if entry[1] == service]
        for (identifier, _, title), rule in zip(entries, rules, strict=True):
            if identifier != requested:
                continue
            if service == "s3":
                remediation = _S3_REMEDIATION[rule.required_fact]
            elif service == "ec2":
                remediation = _EC2_REMEDIATION
            else:
                remediation = rule.remediation
            return {"Check": identifier, "Title": title, "Service": service,
                    "Required fact": rule.required_fact, "Remediation": remediation,
                    "Scope": _SCOPES.get(service, "Regional configuration indicators; effective access is not determined.")}
    return None
