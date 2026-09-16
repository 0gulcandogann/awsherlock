"""S3 public access safeguards; no assertion of effective anonymous access."""

from awsherlock.models import Finding, JSONValue, Resource, Severity
from awsherlock.s3_facts import validate_fact


class S3PublicAccessRule:
    required_fact = "public_access_block"

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != "s3" or resource.resource_type != "bucket":
            return []
        if "public_access_block" not in resource.data:
            raise ValueError("S3 public access block facts were not collected")
        configuration = resource.data["public_access_block"]
        keys = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
        if configuration is not None:
            if not isinstance(configuration, dict) or any(type(configuration.get(key)) is not bool for key in keys):
                raise ValueError("Invalid S3 public access block facts")
            if all(configuration[key] for key in keys):
                return []
        return [Finding(
            id="AWSH-S3-001", title="S3 bucket public access safeguards are incomplete",
            description="Bucket-level Block Public Access is missing or not fully enabled. "
                        "This is potential exposure, not confirmation of public access.",
            severity=Severity.MEDIUM, service="s3", account_id=resource.account_id,
            region=resource.region, resource_id=resource.resource_id, resource_arn=resource.resource_arn,
            evidence={"public_access_block": configuration, "scope": "bucket"},
            risk="Public policies or ACLs may expose data. Account-level controls may still block access; "
                 "effective access and account-level settings were not evaluated.",
            remediation="Review intended access and enable all four bucket Block Public Access settings.",
            references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
        )]


def _fact(resource: Resource, name: str) -> JSONValue:
    if name not in resource.data:
        raise ValueError("Required S3 facts were not collected")
    value = resource.data[name]
    validate_fact(name, value)
    return value


def _finding(resource: Resource, number: str, title: str, description: str,
             fact: str, risk: str, remediation: str, severity: Severity = Severity.MEDIUM) -> list[Finding]:
    return [Finding(
        id=f"AWSH-S3-{number}", title=title, description=description, severity=severity,
        service="s3", account_id=resource.account_id, region=resource.region,
        resource_id=resource.resource_id, resource_arn=resource.resource_arn,
        evidence={fact: resource.data[fact]}, risk=risk, remediation=remediation,
        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"],
    )]


class S3EncryptionRule:
    required_fact = "encryption"

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != "s3" or resource.resource_type != "bucket":
            return []
        algorithms = _fact(resource, self.required_fact)
        if algorithms is not None and all(value in {"AES256", "aws:kms", "aws:kms:dsse"} for value in algorithms):
            return []
        return _finding(resource, "002", "S3 default encryption configuration needs review",
                        "The configuration is absent or uses an unrecognized algorithm. "
                        "S3 automatically encrypts new uploads; this does not prove objects are unencrypted.",
                        self.required_fact, "The intended default encryption configuration cannot be confirmed. "
                        "Existing objects and KMS key permissions were not inspected.",
                        "Review the default encryption configuration and select SSE-S3, SSE-KMS, or DSSE-KMS.", Severity.LOW)


class S3VersioningRule:
    required_fact = "versioning"

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != "s3" or resource.resource_type != "bucket":
            return []
        if _fact(resource, self.required_fact) == "Enabled":
            return []
        return _finding(resource, "003", "S3 bucket versioning is not enabled",
                        "Versioning is absent or suspended.", self.required_fact,
                        "Overwrites and deletions may make data recovery harder.",
                        "Enable bucket versioning and review lifecycle retention requirements.")


class S3LoggingRule:
    required_fact = "logging"

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != "s3" or resource.resource_type != "bucket":
            return []
        if _fact(resource, self.required_fact) is not None:
            return []
        return _finding(resource, "004", "S3 server access logging is disabled",
                        "No server access logging destination is configured.", self.required_fact,
                        "Server access logs will not be available for investigations. "
                        "Alternative logging such as CloudTrail was not evaluated.",
                        "Configure an appropriate server access logging destination.", Severity.LOW)


class S3BucketPolicyRule:
    required_fact = "policy_public"

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != "s3" or resource.resource_type != "bucket":
            return []
        if _fact(resource, self.required_fact) is not True:
            return []
        return _finding(resource, "005", "S3 bucket policy is classified as public",
                        "S3 GetBucketPolicyStatus reports IsPublic=true. "
                        "This policy classification does not prove effective anonymous access.",
                        self.required_fact, "The policy may permit broad access. Block Public Access and other "
                        "controls may still restrict requests; effective permissions were not evaluated.",
                        "Review the bucket policy and restrict access to intended principals and conditions.", Severity.HIGH)


S3_RULES = (S3PublicAccessRule(), S3EncryptionRule(), S3VersioningRule(), S3LoggingRule(), S3BucketPolicyRule())
