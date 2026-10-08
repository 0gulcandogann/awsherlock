"""Amazon Bedrock configuration rules over normalized evidence only."""

from dataclasses import dataclass

from awsherlock.models import Finding, Resource, Severity


@dataclass(frozen=True)
class BedrockGuardrailRule:
    number: int = 1
    required_fact: str = "guardrail_configuration"
    title: str = "Bedrock Agents Classic DRAFT configuration has no associated Guardrail"
    remediation: str = (
        "Review the current DRAFT configuration and attach and test an appropriate Guardrail "
        "before preparing or deploying it; verify published versions and aliases separately."
    )

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != "bedrock" or resource.resource_type != "agent":
            return []
        if self.required_fact not in resource.data:
            raise ValueError("Bedrock Agent Guardrail evidence was not collected")
        if resource.data.get("agent_version") != "DRAFT":
            raise ValueError("Bedrock Agent Guardrail evidence requires DRAFT context")
        configuration = resource.data[self.required_fact]
        if not isinstance(configuration, dict) or set(configuration) != {"identifier", "version"}:
            raise ValueError("Invalid Bedrock Agent Guardrail evidence")
        identifier = configuration["identifier"]
        version = configuration["version"]
        if isinstance(identifier, str) and isinstance(version, str):
            return []
        if identifier is not None or version is not None:
            raise ValueError("Incomplete Bedrock Agent Guardrail evidence")
        return [Finding(
            id="AWSH-BEDROCK-001",
            title=self.title,
            description=(
                "The current Amazon Bedrock Agents Classic DRAFT configuration has no associated "
                "Guardrail. Published versions, aliases, reachability, and exploitability were not evaluated."
            ),
            severity=Severity.MEDIUM,
            service="bedrock",
            account_id=resource.account_id,
            region=resource.region,
            resource_id=resource.resource_id,
            resource_arn=resource.resource_arn,
            evidence={self.required_fact: configuration},
            risk=(
                "The current DRAFT configuration lacks the content-policy control represented "
                "by an associated Guardrail."
            ),
            remediation=self.remediation,
            references=[
                "https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_GetAgent.html",
                "https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_GuardrailConfiguration.html",
            ],
        )]


@dataclass(frozen=True)
class BedrockRuntimeLoggingRule:
    number: int = 2
    required_fact: str = "model_invocation_logging_configuration"
    title: str = "Bedrock Runtime model invocation logging has no active configuration in scanned region"
    remediation: str = (
        "Review audit and data-governance requirements for the Bedrock Runtime logging facility. "
        "If appropriate, configure at least one supported modality and destination, and protect "
        "the potentially sensitive model request and response data with suitable access, "
        "encryption, and retention controls."
    )

    def evaluate(self, resource: Resource) -> list[Finding]:
        if resource.service != "bedrock" or resource.resource_type != "regional-settings":
            return []
        if self.required_fact not in resource.data:
            raise ValueError("Bedrock Runtime logging evidence was not collected")
        configuration = resource.data[self.required_fact]
        if not isinstance(configuration, dict) or set(configuration) != {
            "configured", "destinations", "modalities",
        }:
            raise ValueError("Invalid Bedrock Runtime logging evidence")
        configured = configuration["configured"]
        destinations = configuration["destinations"]
        modalities = configuration["modalities"]
        if (type(configured) is not bool or not isinstance(destinations, list)
                or not isinstance(modalities, list)):
            raise ValueError("Invalid Bedrock Runtime logging evidence")
        if configured and destinations and modalities:
            return []
        return [Finding(
            id="AWSH-BEDROCK-002",
            title=self.title,
            description=(
                "The scanned account and region have no active Amazon Bedrock Runtime model invocation "
                "logging configuration with both a recognized destination and enabled modality. This "
                "does not assess logging or observability for every Bedrock inference endpoint."
            ),
            severity=Severity.LOW,
            service="bedrock",
            account_id=resource.account_id,
            region=resource.region,
            resource_id=resource.resource_id,
            resource_arn=None,
            evidence={self.required_fact: configuration},
            risk="Bedrock Runtime model invocations may have reduced audit evidence in the scanned regional scope.",
            remediation=self.remediation,
            references=[
                "https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                "https://docs.aws.amazon.com/bedrock/latest/APIReference/"
                "API_GetModelInvocationLoggingConfiguration.html",
            ],
        )]


BEDROCK_RULES = (BedrockGuardrailRule(), BedrockRuntimeLoggingRule())
