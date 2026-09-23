"""Rules for normalized RDS snapshot sharing facts."""

from dataclasses import dataclass

from awsherlock.models import Finding, Resource, Severity


@dataclass(frozen=True)
class PublicManualSnapshotRule:
    number: int = 1
    required_fact: str = "restore_public"
    title: str = "Manual RDS snapshot is publicly restorable"
    remediation: str = "Review intended sharing and remove public restore permission from the manual snapshot."

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != "rds" or resource.resource_type not in {"db-snapshot", "db-cluster-snapshot"}:
            return []
        if self.required_fact not in resource.data:
            raise ValueError("RDS snapshot sharing fact was not collected")
        if resource.data[self.required_fact] is not True:
            return []
        return [Finding(id="AWSH-RDS-001", title=self.title,
                        description="The manual snapshot grants public restore access; an actual copy or data read was not observed.",
                        severity=Severity.HIGH, service="rds", account_id=resource.account_id,
                        region=resource.region, resource_id=resource.resource_id,
                        resource_arn=resource.resource_arn,
                        evidence={"snapshot_type": resource.resource_type, "restore_public": True},
                        risk="Any AWS account may copy or restore this snapshot.",
                        remediation=self.remediation,
                        references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.Public.html",
                                    "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-share-snapshot.public.html"])]


RDS_RULES = (PublicManualSnapshotRule(),)
