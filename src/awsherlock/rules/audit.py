"""CloudTrail and KMS risk indicators."""

from dataclasses import dataclass
from awsherlock.models import Finding, Resource, Severity


@dataclass(frozen=True)
class AuditRule:
    service: str
    number: int
    required_fact: str
    title: str
    remediation: str

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != self.service:
            return []
        if self.required_fact not in resource.data:
            raise ValueError("Required audit facts were not collected")
        value = resource.data[self.required_fact]
        if self.service == "cloudtrail":
            prefix = "CT"
            if self.number == 1:
                matches = {"usable": False} if value is False else []
            elif self.number == 4:
                matches = {"management_events": False} if value is False else []
            elif self.number == 2:
                matches = value if not value["IsMultiRegionTrail"] or not value["IncludeGlobalServiceEvents"] else []
            else:
                matches = value if not value["LogFileValidationEnabled"] else []
        else:
            prefix = "KMS"
            if self.number == 1:
                matches = value if value["eligible"] and not value["enabled"] else []
            else:
                matches = [s for s in value if s["effect"] == "Allow" and s["broad_principal"]]
        if not matches:
            return []
        return [Finding(id=f"AWSH-{prefix}-{self.number:03}", title=self.title,
                        description=self.title + ". Review this configuration indicator in its account and regional context.",
                        severity=Severity.HIGH if self.service == "cloudtrail" and self.number == 1 else Severity.MEDIUM,
                        service=self.service, account_id=resource.account_id, region=resource.region,
                        resource_id=resource.resource_id, resource_arn=resource.resource_arn,
                        evidence={self.required_fact: matches}, risk="Audit gaps or overly broad access can weaken detection and protection.",
                        remediation=self.remediation, references=[f"https://docs.aws.amazon.com/{self.service}/"])]


CLOUDTRAIL_RULES = (
    AuditRule("cloudtrail", 1, "usable_trail", "No usable CloudTrail trail visible in scanned region", "Review logging state, S3 destination and delivery errors; configure an appropriate trail."),
    AuditRule("cloudtrail", 2, "trail_settings", "CloudTrail multi-region or global event logging is incomplete", "Review regional coverage and global service event logging."),
    AuditRule("cloudtrail", 3, "trail_settings", "CloudTrail log file validation is disabled", "Enable log file validation and validate delivered log integrity."),
    AuditRule("cloudtrail", 4, "management_events", "CloudTrail management-event logging is excluded", "Review basic or advanced event selectors and include the intended management events; read/write filters may still limit coverage."),
)
KMS_RULES = (
    AuditRule("kms", 1, "rotation", "Eligible KMS key automatic rotation is disabled", "Review your rotation policy and enable automatic rotation when appropriate."),
    AuditRule("kms", 2, "policy", "KMS key policy allows a broad principal", "Review broad principals together with conditions and denies; Resource * alone is not a vulnerability."),
)
