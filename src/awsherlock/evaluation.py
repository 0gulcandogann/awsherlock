"""Shared live/offline evaluation and structured report data."""

from dataclasses import asdict, dataclass, field
from awsherlock.collectors.common import CollectionIssue
from awsherlock.engine import evaluate_rules
from awsherlock.models import Finding, Resource, Severity
from awsherlock.coverage import coverage_status
from awsherlock.scanner import service_components
from awsherlock.snapshot import FACTS, Snapshot
from awsherlock.catalog import check_catalog


@dataclass
class Report:
    metadata: dict
    findings: list[Finding]
    coverage: list[dict]
    identities: list[dict] = field(default_factory=list)

    @property
    def incomplete(self) -> bool:
        return any(entry["status"] != "COMPLETE" for entry in self.coverage)

    def to_dict(self) -> dict:
        return {**({"identities": self.identities} if self.identities else {}), "metadata": self.metadata, "coverage": self.coverage,
                "findings": [finding.to_dict() for finding in self.findings],
                "summary": {"resources": sum(entry["resources"] for entry in self.coverage),
                            "findings": len(self.findings), "checks_evaluated": sum(entry["evaluated"] for entry in self.coverage),
                            "incomplete": self.incomplete,
                            "severity": {severity.value: sum(f.severity == severity for f in self.findings) for severity in Severity}}}


def cloudtrail_missing_fact_issue(resource: Resource, identifier: str, fact: str,
                                  collection_issues: list[CollectionIssue]) -> dict:
    """Explain absent CloudTrail facts without exporting raw collector payloads."""
    operation = {"management_events": "GetEventSelectors", "management_excluded_sources": "GetEventSelectors",
                 "trail_settings": "TrailSettings"}.get(fact)
    failed = any(issue.operation == operation and issue.resource_id in {None, resource.resource_id}
                 for issue in collection_issues) if operation else bool(collection_issues)
    reason = ("a related collection issue is recorded separately" if failed else
              "the fact is absent from this snapshot")
    return asdict(CollectionIssue(resource.resource_id, "RequiredFact",
                                  f"{identifier} requires {fact}; {reason}."))


def s3_missing_fact_issue(resource: Resource, identifier: str, fact: str,
                          collection_issues: list[CollectionIssue]) -> dict:
    """Tie absent bucket facts to only that bucket's known read failure."""
    operation = {"public_access_block": "GetPublicAccessBlock", "encryption": "GetBucketEncryption",
                 "versioning": "GetBucketVersioning", "logging": "GetBucketLogging",
                 "policy_public": "GetBucketPolicyStatus"}[fact]
    failed = any(issue.operation == operation and issue.resource_id == resource.resource_id
                 for issue in collection_issues)
    reason = ("a related collection issue is recorded separately" if failed else
              "the fact is absent from this snapshot")
    return asdict(CollectionIssue(resource.resource_id, "RequiredFact",
                                  f"{identifier} requires {fact}; {reason}."))


def secret_missing_fact_issue(resource: Resource, identifier: str, fact: str,
                              collection_issues: list[CollectionIssue]) -> dict:
    """Explain absent secret metadata without exposing policy or key details."""
    operation = {"rotation": "RotationMetadata", "policy": "GetResourcePolicy",
                 "encryption": "DescribeKey"}[fact]
    failed = any(issue.operation == operation and issue.resource_id == resource.resource_id
                 for issue in collection_issues)
    reason = ("a related collection issue is recorded separately" if failed else
              "the fact is absent from this snapshot")
    return asdict(CollectionIssue(resource.resource_id, "RequiredFact",
                                  f"{identifier} requires {fact}; {reason}."))


def lambda_missing_fact_issue(resource: Resource, identifier: str, fact: str,
                              collection_issues: list[CollectionIssue]) -> dict:
    """Explain absent function facts without exposing code or environment values."""
    operation = {"urls": "ListFunctionUrlConfigs", "role_policies": "ListAttachedRolePolicies",
                 "runtime": "ManagedRuntime (images/unknown runtimes not scanned)"}[fact]
    failed = any(issue.operation == operation and issue.resource_id == resource.resource_id
                 for issue in collection_issues)
    reason = ("a related collection issue is recorded separately" if failed else
              "the fact is absent from this snapshot")
    return asdict(CollectionIssue(resource.resource_id, "RequiredFact",
                                  f"{identifier} requires {fact}; {reason}."))


def kms_missing_fact_issue(resource: Resource, identifier: str, fact: str,
                           collection_issues: list[CollectionIssue]) -> dict:
    """Explain absent key facts without including policy or key material."""
    operation = {"rotation": "GetKeyRotationStatus", "policy": "GetKeyPolicy"}[fact]
    failed = any(issue.operation == operation and issue.resource_id == resource.resource_id
                 for issue in collection_issues)
    reason = ("a related collection issue is recorded separately" if failed else
              "the fact is absent from this snapshot")
    return asdict(CollectionIssue(resource.resource_id, "RequiredFact",
                                  f"{identifier} requires {fact}; {reason}."))


def finalize_resource_selection(report: Report) -> None:
    """Unmatched selectors are assessed once across all account/region scopes."""
    selected = report.metadata.get("selected_resources", [])
    matched = set(report.metadata.get("matched_resource_selectors", []))
    unmatched = [selector for selector in selected if selector not in matched]
    if unmatched:
        report.coverage.append({"account_id": report.metadata["account_id"], "service": "selection", "status": "NOT_SCANNED",
                                "resources": 0, "evaluated": 0, "not_scanned": 0, "findings": 0,
                                "issues": [{"resource_id": selector, "operation": "ResourceSelection",
                                            "message": "Requested resource was not discovered in the selected scope"} for selector in unmatched]})


def evaluate_snapshot(snapshot: Snapshot, selected_checks: list[str] | None = None,
                      selected_resources: list[str] | None = None, *, report_unmatched: bool = True,
                      identity_governance: bool = False, identity_inventory: dict | None = None) -> Report:
    # Common validation prevents malformed offline data from being treated as PASS.
    metadata = snapshot.to_dict()["metadata"]
    if identity_inventory is not None:
        from awsherlock.identity_config import validate_inventory
        validate_inventory(identity_inventory)
    matched_resources = set()
    if selected_resources is not None:
        metadata["selected_resources"] = list(selected_resources)
    identifiers = {service: [identifier for identifier, owner, _ in check_catalog() if owner == service]
                   for service in snapshot.services}
    if selected_checks is not None:
        known = {identifier for entries in identifiers.values() for identifier in entries}
        if not set(selected_checks) <= known:
            raise ValueError("Selected checks are absent from the selected services/snapshot")
        metadata["selected_checks"] = list(selected_checks)
    findings = []
    coverage = []
    identities = []
    for service, collection in snapshot.services.items():
        _, rules = service_components(service)
        issues = [asdict(issue) for issue in collection.issues]
        excluded = ([identifier for identifier in identifiers[service] if identifier not in selected_checks]
                    if selected_checks is not None else [])
        if excluded:
            issues.append(asdict(CollectionIssue(None, "CheckSelection", "Checks excluded by selection: " + ", ".join(excluded))))
        evaluated = missing = found = 0
        for resource in collection.resources:
            governance = (identity_governance or resource.data.get("identity_requested", False)
                          or selected_checks is not None and any(identifier.startswith("AWSH-IAM-") and int(identifier.rsplit("-", 1)[1]) >= 7 for identifier in selected_checks))
            if governance and identity_inventory is not None and resource.service == "iam" and resource.resource_type in {"role", "user"}:
                from dataclasses import replace
                from awsherlock.identity_config import approval_fact
                resource = replace(resource, data={**resource.data, "identity_approval": approval_fact(resource.account_id, resource.resource_arn, identity_inventory)})
            matches = ({resource.resource_id, resource.resource_arn} & set(selected_resources)
                       if selected_resources is not None else set())
            matched_resources.update(matches)
            resource_excluded = selected_resources is not None and not matches
            if resource_excluded:
                issues.append(asdict(CollectionIssue(resource.resource_id, "ResourceSelection", "Resource excluded by --resources")))
            if not resource_excluded and service == "s3" and "account_public_access_block" not in resource.data:
                issues.append(asdict(CollectionIssue(resource.resource_id, "AccountPublicAccessContext",
                                                     "Account public-access facts are missing; context was not scanned")))
            allowed = FACTS[(service, resource.resource_type)]
            for identifier, rule in zip(identifiers[service], rules, strict=True):
                if service == "iam" and rule.number >= 7:
                    if not governance or resource.resource_type not in {"role", "user"} or rule.number == 12 and resource.resource_type != "role":
                        continue
                fact = rule.required_fact
                if fact not in allowed:
                    continue
                if service == "iam" and fact == "key_stale" and resource.data.get("key_age", {}).get("active") is False:
                    continue
                if service == "kms" and fact == "policy" and resource.data.get("rotation", {}).get("reason") == "AWS-managed key":
                    continue
                if identifier in excluded or resource_excluded:
                    missing += 1
                    continue
                if fact not in resource.data:
                    missing += 1
                    if service == "cloudtrail":
                        issues.append(cloudtrail_missing_fact_issue(resource, identifier, fact, collection.issues))
                    elif service == "s3":
                        issues.append(s3_missing_fact_issue(resource, identifier, fact, collection.issues))
                    elif service == "secretsmanager":
                        issues.append(secret_missing_fact_issue(resource, identifier, fact, collection.issues))
                    elif service == "lambda":
                        issues.append(lambda_missing_fact_issue(resource, identifier, fact, collection.issues))
                    elif service == "kms":
                        issues.append(kms_missing_fact_issue(resource, identifier, fact, collection.issues))
                    continue
                if service == "cloudtrail" and identifier == "AWSH-CT-004" and resource.data[fact] is True:
                    missing_context = [name for name in ("management_excluded_sources", "management_event_types")
                                       if name not in resource.data]
                    if missing_context:
                        missing += 1
                        issues.extend(cloudtrail_missing_fact_issue(resource, identifier, name, collection.issues)
                                      for name in missing_context)
                        continue
                try:
                    result = evaluate_rules([resource], [rule])
                    findings.extend(result)
                    found += len(result)
                    evaluated += 1
                except (ValueError, TypeError, KeyError, AttributeError):
                    missing += 1
                    issues.append(asdict(CollectionIssue(resource.resource_id, "RuleEvaluation", "Invalid rule facts")))
            if governance and service == "iam" and resource.resource_type in {"role", "user"}:
                from awsherlock.identity_reporting import identity_summary
                identities.append(identity_summary(resource, resource_excluded))
        status = coverage_status(issues, evaluated, missing)
        if not evaluated and issues and all(issue["operation"] in {"AccountPublicAccessContext", "CheckSelection", "ResourceSelection", "RequiredFact"} for issue in issues):
            status = "NOT_SCANNED"
        coverage.append({"account_id": snapshot.metadata.account_id, "service": service, "status": status, "resources": len(collection.resources),
                         "evaluated": evaluated, "not_scanned": missing, "findings": found, "issues": issues})
    report = Report(metadata, findings, coverage, identities)
    if selected_resources is not None:
        metadata["matched_resource_selectors"] = sorted(matched_resources)
        if report_unmatched:
            finalize_resource_selection(report)
    return report
