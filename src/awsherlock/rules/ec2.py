"""EC2 configuration indicators; routing and effective reachability are not assessed."""

from dataclasses import dataclass
from awsherlock.models import Finding, Resource, Severity


@dataclass(frozen=True)
class EC2Rule:
    number: int
    required_fact: str
    title: str
    ports: tuple[int, ...] = ()

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != "ec2":
            return []
        if self.required_fact not in resource.data:
            raise ValueError("Required EC2 facts were not collected")
        value = resource.data[self.required_fact]
        if self.ports:
            matches = [permission for permission in value
                       if any(cidr in {"0.0.0.0/0", "::/0"} for cidr in permission["cidrs"])
                       and (permission["protocol"] == "-1" or
                            (permission["protocol"] in ({"tcp", "6"} if self.number == 1 else {"tcp", "6", "udp", "17"})
                             and any(permission["from"] <= port <= permission["to"] for port in self.ports)))]
        elif self.number == 4:
            matches = value if value["endpoint"] == "enabled" and value["tokens"] == "optional" else []
        elif self.number == 5:
            matches = value
        else:
            matches = {"encrypted": False} if value is False else []
        if not matches:
            return []
        return [Finding(
            id=f"AWSH-EC2-{self.number:03}", title=self.title, description=self.title + ". "
            "This is configuration evidence; network routes, NACLs, and application controls are not evaluated.",
            severity=Severity.MEDIUM if self.number in {4, 5} else Severity.HIGH,
            service="ec2", account_id=resource.account_id, region=resource.region,
            resource_id=resource.resource_id, resource_arn=resource.resource_arn,
            evidence={self.required_fact: matches}, risk="The configuration may expose workloads or weaken protection of instance data.",
            remediation="Restrict ingress and public addressing; require IMDSv2 and use encrypted EBS volumes as applicable.",
            references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"],
        )]


EC2_RULES = (
    EC2Rule(1, "ingress", "Security group permits internet-wide SSH", (22,)),
    EC2Rule(2, "ingress", "Security group permits internet-wide RDP", (3389,)),
    EC2Rule(3, "ingress", "Security group permits internet-wide database access", (1433, 1521, 3306, 5432, 6379, 9042, 9200, 27017)),
    EC2Rule(4, "metadata", "Instance permits IMDSv1"),
    EC2Rule(5, "addresses", "Instance has public IPv4 or IPv6 addressing"),
    EC2Rule(6, "encrypted", "EBS volume is not encrypted"),
)
