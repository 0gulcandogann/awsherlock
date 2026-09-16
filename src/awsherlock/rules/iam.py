"""IAM risk indicators, not an effective-permission simulation."""

from dataclasses import dataclass

from awsherlock.models import Finding, Resource, Severity


@dataclass(frozen=True)
class IAMRule:
    number: int
    required_fact: str
    title: str
    remediation: str

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != "iam":
            return []
        if self.required_fact not in resource.data:
            raise ValueError("Required IAM facts were not collected")
        value = resource.data[self.required_fact]
        if self.number == 1:
            matches = [arn for arn in value if arn.split(":", 5)[-1] == "policy/AdministratorAccess"
                       and len(arn.split(":")) == 6 and arn.split(":")[4] == "aws"]
        elif self.number in (2, 3):
            key = "actions" if self.number == 2 else "resources"
            matches = [statement for statement in value if statement["effect"] == "Allow"
                       and (statement[f"not_{key}"] or any("*" in item or "?" in item for item in statement[key]))]
        elif self.number == 4:
            matches = value if value["console"] and not value["mfa"] else []
        elif self.number == 5:
            matches = value if value["active"] and value["days"] > 90 else []
        else:
            matches = value if value["days"] > 90 else []
        if not matches:
            return []
        return [Finding(
            id=f"AWSH-IAM-{self.number:03}", title=self.title,
            description="IAM configuration risk indicator. Conditions, explicit denies, permission boundaries, "
                        "and organization controls may restrict effective access." if self.number <= 3 else self.title + ". Threshold: 90 days for key checks.",
            severity=Severity.HIGH if self.number in (1, 4) else Severity.MEDIUM,
            service="iam", account_id=resource.account_id, region=None,
            resource_id=resource.resource_id, resource_arn=resource.resource_arn,
            evidence={self.required_fact: matches}, risk="Overprivileged or poorly protected credentials may increase unauthorized access risk.",
            remediation=self.remediation,
            references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
        )]


IAM_RULES = (
    IAMRule(1, "attached", "AdministratorAccess is directly attached", "Replace broad administrative access with task-specific permissions."),
    IAMRule(2, "statements", "Policy allows wildcard actions or NotAction", "Review wildcard/complement actions and narrow permissions where possible."),
    IAMRule(3, "statements", "Policy allows wildcard resources or NotResource", "Scope resources where the actions support resource-level permissions."),
    IAMRule(4, "console_mfa", "Console user has no registered MFA device", "Register and enforce MFA for console access."),
    IAMRule(5, "key_age", "Active access key is older than 90 days", "Prefer temporary credentials; rotate required long-lived keys."),
    IAMRule(6, "key_stale", "Active access key is potentially stale", "Review keys unused for over 90 days and disable unnecessary credentials."),
)
