"""Pure, conservative diagnostics derived from normalized snapshot evidence."""

from collections import Counter
import hashlib
import json

from awsherlock.evaluation import Report
from awsherlock.branding import terminal_text
from awsherlock.registry import SERVICE_SPECS, service_spec
from awsherlock.snapshot import Snapshot


SCHEMA_VERSION = 1

# Exact normalized operation labels that existing collectors/evaluation can
# persist. This is an export boundary, not an AWS permission or dispatch list.
_EVALUATION_OPERATIONS = frozenset({
    "AccountPublicAccessContext", "AccountSelection", "CheckSelection",
    "OUSelection", "RequiredCollection", "RequiredFact", "ResourceSelection",
    "RuleEvaluation", "SnapshotValidation",
})
_COLLECTION_OPERATIONS = {
    "iam": frozenset({
        "AuthorizationDetails", "ConsoleMFA", "GetAccessKeyLastUsed",
        "GetAccountAuthorizationDetails", "GetAgent", "GetAgentRuntime",
        "GetAgentRuntimeEndpoint", "GetInstanceProfile", "GetLoginProfile",
        "GetPolicy", "GetPolicyVersion", "GetRole", "GetRolePolicy",
        "IdentityAnalyzers", "IdentityBinding", "IdentityBindings",
        "IdentityEvents", "IdentityManagedPolicy", "IdentityPolicyContext",
        "IdentityProfile", "ListAccessKeys", "ListAgentRuntimeEndpoints",
        "ListAgentRuntimes", "ListAgents", "ListAttachedRolePolicies",
        "ListFunctions", "ListMFADevices", "ListRoleTags", "ListUserTags",
        "PolicyNormalization", "RoleLastUsed", "RoleTrust",
    }),
    "s3": frozenset({
        "AccountPublicAccessBlock", "CreateRegionalClient", "GetAccountPublicAccessBlock",
        "GetBucketEncryption", "GetBucketLocation", "GetBucketLogging",
        "GetBucketPolicyStatus", "GetBucketVersioning", "GetPublicAccessBlock", "ListBuckets",
    }),
    "ec2": frozenset({
        "DescribeInstances", "DescribeSecurityGroups", "DescribeVolumes",
        "EC2Client", "Region", "describe_instances", "describe_instances.addresses",
        "describe_instances.metadata", "describe_security_groups", "describe_volumes",
    }),
    "lambda": frozenset({
        "LambdaMetadata", "ListAttachedRolePolicies", "ListFunctionUrlConfigs",
        "ListFunctions", "ManagedRuntime (images/unknown runtimes not scanned)", "Region",
    }),
    "secretsmanager": frozenset({
        "DescribeKey", "GetResourcePolicy", "ListSecrets", "Region", "RotationMetadata",
        "SecretMetadata",
    }),
    "cloudtrail": frozenset({
        "DescribeTrails", "GetEventSelectors", "GetTrailStatus", "Region", "TrailMetadata",
        "TrailSettings",
    }),
    "kms": frozenset({"DescribeKey", "GetKeyPolicy", "GetKeyRotationStatus", "ListKeys", "Region"}),
    "rds": frozenset({
        "DescribeDBClusterSnapshotAttributes", "DescribeDBClusterSnapshots",
        "DescribeDBInstances", "DescribeDBSnapshotAttributes", "DescribeDBSnapshots", "Region",
        "RDSClient",
    }),
    "guardduty": frozenset({"GetDetector", "ListDetectors", "Region"}),
    "dynamodb": frozenset({"DescribeContinuousBackups", "ListTables", "Region"}),
    "bedrock": frozenset({
        "GetAgent", "GetModelInvocationLoggingConfiguration", "ListAgents", "Region",
    }),
}

_MESSAGE_REASONS = {
    "AccessDenied": "ACCESS_DENIED",
    "AWS request throttled": "THROTTLED",
    "Invalid AWS response": "INVALID_RESPONSE",
    "AWS request timed out": "REQUEST_TIMEOUT",
    "AWS endpoint connection failed": "ENDPOINT_CONNECTION_FAILED",
    "AWS credentials expired or invalid": "CREDENTIALS_INVALID",
    "Event history page/time budget exhausted": "BUDGET_EXHAUSTED",
    "Event history time budget exhausted": "BUDGET_EXHAUSTED",
}
_OPERATION_REASONS = {
    "RequiredFact": "EVALUATION_INCOMPLETE",
    "RuleEvaluation": "EVALUATION_INCOMPLETE",
    "SnapshotValidation": "EVALUATION_INCOMPLETE",
    "RequiredCollection": "COLLECTION_INCOMPLETE",
    "CheckSelection": "SCOPE_NOT_RECORDED",
    "ResourceSelection": "SCOPE_NOT_RECORDED",
    "AccountSelection": "SCOPE_NOT_RECORDED",
    "OUSelection": "SCOPE_NOT_RECORDED",
    "AccountPublicAccessContext": "SCOPE_NOT_RECORDED",
}
_EXPLANATIONS = {
    "ACCESS_DENIED": "AWS denied a recorded read; the affected evidence is incomplete.",
    "THROTTLED": "AWS throttled a recorded read; the affected evidence is incomplete.",
    "INVALID_RESPONSE": "A recorded response could not be validated as normalized evidence.",
    "REQUEST_TIMEOUT": "A recorded AWS read timed out before complete evidence was obtained.",
    "ENDPOINT_CONNECTION_FAILED": "A recorded AWS endpoint connection failed.",
    "CREDENTIALS_INVALID": "The recorded collection could not continue with valid AWS credentials.",
    "BUDGET_EXHAUSTED": "A recorded evidence read stopped at its configured page or time budget.",
    "EVALUATION_INCOMPLETE": "A registered evaluation lacked validated evidence required for a conclusion.",
    "COLLECTION_INCOMPLETE": "A required collection completion marker is absent.",
    "SCOPE_NOT_RECORDED": "Requested scope or evaluation evidence was not recorded in this result.",
    "CAUSE_NOT_ESTABLISHED": "Collection is incomplete, but the normalized evidence does not establish a specific cause.",
}


def _reason(operation: object, message: object) -> str:
    if isinstance(operation, str) and operation in _OPERATION_REASONS:
        return _OPERATION_REASONS[operation]
    if isinstance(message, str):
        return _MESSAGE_REASONS.get(message, "CAUSE_NOT_ESTABLISHED")
    return "CAUSE_NOT_ESTABLISHED"


def _operation(service: str, value: object) -> str | None:
    if not isinstance(value, str):
        return None
    allowed = _COLLECTION_OPERATIONS.get(service, frozenset()) | _EVALUATION_OPERATIONS
    return value if value in allowed else None


def _issue_rows(account_id: str, region: str | None, service: str, issues: list[dict]) -> list[dict]:
    ordered = sorted(issues, key=lambda issue: (
        str(issue.get("operation", "")), str(issue.get("resource_id") or ""),
        _reason(issue.get("operation"), issue.get("message")), str(issue.get("message", "")),
    ))
    duplicates: Counter[tuple[str, str, str]] = Counter()
    result = []
    for issue in ordered:
        reason = _reason(issue.get("operation"), issue.get("message"))
        trusted_operation = _operation(service, issue.get("operation"))
        resource_id = issue.get("resource_id") if isinstance(issue.get("resource_id"), str) else None
        identity = (trusted_operation or "", resource_id or "", reason)
        ordinal = duplicates[identity]
        duplicates[identity] += 1
        digest_material = [account_id, region or "", service, *identity, str(ordinal)]
        digest = hashlib.sha256(json.dumps(digest_material, separators=(",", ":"),
                                           ensure_ascii=True).encode("ascii")).hexdigest()[:20]
        result.append({
            "reason_code": reason,
            "explanation": _EXPLANATIONS[reason],
            "operation": trusted_operation,
            "resource_id": resource_id,
            "issue_reference": {
                "source_field": f"report.coverage.{service}.issues",
                "id": f"issue-{digest}",
                "occurrence": ordinal + 1,
            },
        })
    return result


def _validate_pair(snapshot: Snapshot, report: Report) -> None:
    expected = {
        "scan_id": snapshot.metadata.scan_id,
        "account_id": snapshot.metadata.account_id,
        "region": snapshot.metadata.region,
    }
    if any(report.metadata.get(key) != value for key, value in expected.items()):
        raise ValueError("Report scope does not match source snapshot")


def build_coverage_diagnostics(snapshot: Snapshot, report: Report) -> dict:
    """Build diagnostic presentation data without collecting or re-evaluating."""
    _validate_pair(snapshot, report)
    coverage = {row["service"]: row for row in report.coverage}
    services = []
    for service in sorted(snapshot.services):
        row = coverage[service]
        spec = service_spec(service)
        collection = snapshot.services[service]
        service_region = None if service in {"iam", "s3"} else snapshot.metadata.region
        related = sum(
            edge.source.service == service or edge.target.service == service
            for edge in snapshot.relationships
        )
        services.append({
            "account_id": snapshot.metadata.account_id,
            "region": service_region,
            "scope": "global" if service == "iam" else "bucket" if service == "s3" else "regional",
            "service": service,
            "registered_mode": "DEFAULT" if spec.default_enabled else "OPT_IN",
            "recorded": True,
            "coverage_status": row["status"],
            "recorded_evidence": {
                "resources": len(collection.resources),
                "findings": row["findings"],
                "checks_evaluated": row["evaluated"],
                "checks_not_scanned": row["not_scanned"],
                "relationships": related,
                "completed_operations": sorted(collection.completed_operations),
            },
            "limitations": _issue_rows(snapshot.metadata.account_id, service_region, service, row["issues"]),
            "uncertainty": [{
                "reason_code": "COMPLETENESS_NOT_PROVEN",
                "explanation": (
                    "Recorded evidence and successful reads do not prove exhaustive service, resource, "
                    "or relationship enumeration."
                ),
            }],
        })
    recorded = set(snapshot.services)
    unrecorded = [{
        "service": spec.identifier,
        "registered_mode": "DEFAULT" if spec.default_enabled else "OPT_IN",
        "reason_code": "SCOPE_NOT_RECORDED",
        "explanation": "This service is not present in the snapshot; collection history is not established.",
    } for spec in SERVICE_SPECS if spec.identifier not in recorded]
    supports = snapshot.supports_relationships
    source = snapshot.metadata
    return {
        "kind": "coverage-diagnostics",
        "schema_version": SCHEMA_VERSION,
        "source_snapshot": {
            "scan_id": source.scan_id,
            "started_at": source.started_at.isoformat(),
            "account_id": source.account_id,
            "region": source.region,
            "producer_version": source.version,
            "snapshot_schema_version": snapshot.schema_version,
            "supports_relationships": supports,
        },
        "summary": {
            "recorded_services": len(services),
            "incomplete_services": sum(row["coverage_status"] != "COMPLETE" for row in services),
            "recorded_resources": sum(row["recorded_evidence"]["resources"] for row in services),
            "recorded_findings": len(report.findings),
            "recorded_relationships": len(snapshot.relationships),
        },
        "relationship_coverage": {
            "capability": "POSITIVE_ONLY" if supports else "UNSUPPORTED",
            "observed_relationships": len(snapshot.relationships) if supports else 0,
            "reason_code": (
                "RELATIONSHIP_COMPLETENESS_NOT_PROVEN" if supports else "RELATIONSHIPS_UNSUPPORTED"
            ),
            "explanation": (
                "Only positive relationships stored in this snapshot are reportable; absence is not proof of non-use."
                if supports else
                "Snapshot schema v1 cannot represent relationships; availability cannot be inferred."
            ),
        },
        "services": services,
        "unrecorded_services": unrecorded,
        "unsupported_conclusions": [
            "NO_FINDINGS_IS_NOT_SECURITY_PASS",
            "MISSING_RELATIONSHIP_IS_NOT_PROOF_OF_ABSENCE",
            "EFFECTIVE_IAM_PERMISSIONS_NOT_EVALUATED",
            "EXPLOITABILITY_NOT_PROVEN",
            "COMPROMISE_NOT_PROVEN",
            "REAL_TRAFFIC_NOT_PROVEN",
        ],
    }


def render_coverage_json(document: dict) -> str:
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def render_coverage_console(document: dict) -> str:
    source = document["source_snapshot"]
    summary = document["summary"]
    lines = [
        "Coverage Intelligence",
        (f"Scan: {terminal_text(source['scan_id'])} / Account: {terminal_text(source['account_id'])} / "
         f"Region: {terminal_text(source['region'] or 'global')}"),
        (f"Recorded: {summary['recorded_services']} services, {summary['recorded_resources']} resources, "
         f"{summary['recorded_findings']} findings, {summary['recorded_relationships']} relationships"),
        "Service coverage:",
    ]
    for row in document["services"]:
        lines.append(
            f"- {row['service']}: {row['coverage_status']} / "
            f"{len(row['limitations'])} recorded limitation(s)"
        )
        for item in row["limitations"]:
            lines.append(f"  {item['reason_code']}: {item['explanation']}")
    lines.extend([
        ("Relationships: " + document["relationship_coverage"]["capability"] + " / "
         + document["relationship_coverage"]["reason_code"]),
        "Completeness is not proven. Missing findings or relationships are not security conclusions.",
    ])
    return "\n".join(lines) + "\n"
