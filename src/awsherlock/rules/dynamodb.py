"""DynamoDB recovery posture from normalized table facts."""

from dataclasses import dataclass

from awsherlock.models import Finding, Resource, Severity


@dataclass(frozen=True)
class DynamoDBPITRRule:
    number: int = 1
    required_fact: str = "pitr_enabled"
    title: str = "DynamoDB table point-in-time recovery is disabled"
    remediation: str = "Review recovery requirements and PITR pricing before enabling point-in-time recovery for this table."

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != "dynamodb" or resource.resource_type != "table":
            return []
        if self.required_fact not in resource.data:
            raise ValueError("DynamoDB PITR status was not collected")
        if resource.data[self.required_fact] is not False:
            return []
        return [Finding(id="AWSH-DDB-001", title=self.title,
                        description="Point-in-time recovery is disabled for this table; other backup methods were not assessed.",
                        severity=Severity.MEDIUM, service="dynamodb",
                        account_id=resource.account_id, region=resource.region,
                        resource_id=resource.resource_id, resource_arn=resource.resource_arn,
                        evidence={"pitr_enabled": False},
                        risk="The table has no DynamoDB point-in-time recovery window for accidental writes or deletions.",
                        remediation=self.remediation,
                        references=["https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Point-in-time-recovery.html"])]


DYNAMODB_RULES = (DynamoDBPITRRule(),)
