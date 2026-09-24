"""Regional GuardDuty detector posture from normalized facts."""

from dataclasses import dataclass

from awsherlock.models import Finding, Resource, Severity


@dataclass(frozen=True)
class GuardDutyDetectorRule:
    number: int = 1
    required_fact: str = "enabled_detector_present"
    title: str = "No enabled GuardDuty detector in scanned region"
    remediation: str = "Review the regional GuardDuty configuration and enable a detector where required."

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != "guardduty" or resource.resource_type != "regional-summary":
            return []
        if self.required_fact not in resource.data:
            raise ValueError("GuardDuty detector status was not fully observed")
        if resource.data[self.required_fact] is not False:
            return []
        return [Finding(id="AWSH-GD-001", title=self.title,
                        description="No enabled GuardDuty detector was observed for this account and region.",
                        severity=Severity.MEDIUM, service="guardduty",
                        account_id=resource.account_id, region=resource.region,
                        resource_id=resource.resource_id, resource_arn=None,
                        evidence={"enabled_detector_present": False},
                        risk="Regional GuardDuty detection is not enabled for the observed account scope.",
                        remediation=self.remediation,
                        references=["https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html"])]


GUARDDUTY_RULES = (GuardDutyDetectorRule(),)
