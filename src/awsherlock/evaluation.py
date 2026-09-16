"""Shared live/offline evaluation and structured report data."""

from dataclasses import asdict, dataclass
from awsherlock.collectors.common import CollectionIssue
from awsherlock.engine import evaluate_rules
from awsherlock.models import Finding, Severity
from awsherlock.coverage import coverage_status
from awsherlock.scanner import service_components
from awsherlock.snapshot import FACTS, Snapshot


@dataclass
class Report:
    metadata: dict
    findings: list[Finding]
    coverage: list[dict]

    @property
    def incomplete(self) -> bool:
        return any(entry["status"] != "COMPLETE" for entry in self.coverage)

    def to_dict(self) -> dict:
        return {"metadata": self.metadata, "coverage": self.coverage,
                "findings": [finding.to_dict() for finding in self.findings],
                "summary": {"resources": sum(entry["resources"] for entry in self.coverage),
                            "findings": len(self.findings), "checks_evaluated": sum(entry["evaluated"] for entry in self.coverage),
                            "incomplete": self.incomplete,
                            "severity": {severity.value: sum(f.severity == severity for f in self.findings) for severity in Severity}}}


def evaluate_snapshot(snapshot: Snapshot) -> Report:
    # Common validation prevents malformed offline data from being treated as PASS.
    metadata = snapshot.to_dict()["metadata"]
    findings = []
    coverage = []
    for service, collection in snapshot.services.items():
        _, rules = service_components(service)
        issues = [asdict(issue) for issue in collection.issues]
        evaluated = missing = found = 0
        for resource in collection.resources:
            allowed = FACTS[(service, resource.resource_type)]
            for rule in rules:
                fact = rule.required_fact
                if fact not in allowed:
                    continue
                if service == "iam" and fact == "key_stale" and resource.data.get("key_age", {}).get("active") is False:
                    continue
                if service == "kms" and fact == "policy" and resource.data.get("rotation", {}).get("reason") == "AWS-managed key":
                    continue
                if fact not in resource.data:
                    missing += 1
                    continue
                try:
                    result = evaluate_rules([resource], [rule])
                    findings.extend(result)
                    found += len(result)
                    evaluated += 1
                except (ValueError, TypeError, KeyError, AttributeError):
                    missing += 1
                    issues.append(asdict(CollectionIssue(resource.resource_id, "RuleEvaluation", "Invalid rule facts")))
        status = coverage_status(issues, evaluated, missing)
        coverage.append({"account_id": snapshot.metadata.account_id, "service": service, "status": status, "resources": len(collection.resources),
                         "evaluated": evaluated, "not_scanned": missing, "findings": found, "issues": issues})
    return Report(metadata, findings, coverage)
