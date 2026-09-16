"""Lambda and Secrets Manager rules consume sanitized facts only."""

from dataclasses import dataclass
from awsherlock.models import Finding, Resource, Severity


@dataclass(frozen=True)
class ServerlessRule:
    service: str
    number: int
    required_fact: str
    title: str
    remediation: str

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != self.service:
            return []
        if self.required_fact not in resource.data:
            raise ValueError("Required serverless facts were not collected")
        value = resource.data[self.required_fact]
        if self.service == "lambda":
            if self.number == 1:
                matches = [url for url in value if url["auth"] == "NONE"]
            elif self.number == 2:
                matches = [arn for arn in value if arn.split(":", 5)[-1] in {"policy/AdministratorAccess", "policy/PowerUserAccess"}
                           and len(arn.split(":")) == 6 and arn.split(":")[4] == "aws"]
            else:
                matches = value if value["deprecated"] else []
            prefix = "LAMBDA"
        else:
            prefix = "SECRET"
            if self.number == 1:
                matches = {"rotation": False} if value is False else []
            elif self.number == 2:
                matches = [statement for statement in value if statement["effect"] == "Allow" and statement["broad_principal"]]
            else:
                matches = value if value["state"] != "Enabled" else []
        if not matches:
            return []
        return [Finding(id=f"AWSH-{prefix}-{self.number:03}", title=self.title,
                        description=self.title + ". This is a configuration indicator; effective permissions are not simulated.",
                        severity=Severity.HIGH if self.number in {1, 2} and self.service == "lambda" else Severity.MEDIUM,
                        service=self.service, account_id=resource.account_id, region=resource.region,
                        resource_id=resource.resource_id, resource_arn=resource.resource_arn,
                        evidence={self.required_fact: matches}, risk="The configuration may permit unauthorized access or reduce protection and availability.",
                        remediation=self.remediation,
                        references=[f"https://docs.aws.amazon.com/{self.service}/"])]


LAMBDA_RULES = (
    ServerlessRule("lambda", 1, "urls", "Lambda URL does not require IAM authentication", "Review URL access policies and use AWS_IAM authentication where appropriate."),
    ServerlessRule("lambda", 2, "role_policies", "Lambda role has a broad AWS managed policy", "Replace AdministratorAccess/PowerUserAccess with least-privilege execution permissions."),
    ServerlessRule("lambda", 3, "runtime", "Lambda managed runtime is deprecated", "Migrate to a supported runtime; check the AWS runtime schedule before deployment."),
)
SECRET_RULES = (
    ServerlessRule("secretsmanager", 1, "rotation", "Secret automatic rotation is disabled", "Configure and test rotation appropriate for the secret."),
    ServerlessRule("secretsmanager", 2, "policy", "Secret resource policy allows a broad principal", "Review principal scope, conditions and denies; restrict access to intended identities."),
    ServerlessRule("secretsmanager", 3, "encryption", "Secret KMS key is not enabled", "Review KMS key state and restore an appropriate usable encryption key."),
)
