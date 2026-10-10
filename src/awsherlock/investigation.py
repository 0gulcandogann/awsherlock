"""Minimized, deterministic evidence for one existing offline Investigation Lead."""

from copy import deepcopy
import hashlib
import json
import re

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from awsherlock import __version__
from awsherlock.correlation import resource_ref
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.html_report import _safe_https_url
from awsherlock.lead_delta import (
    BROAD, LOCAL_PREDICATES, POLICY_VERSION, _Observation, _edge_key,
    _evidence, _finding_key, _resource_key, _support,
)
from awsherlock.leads import CORRELATION_RULES, investigation_leads
from awsherlock.relationships import RelationshipError, normalize_relationships, relationship_to_dict
from awsherlock.snapshot import Snapshot, SnapshotError


class InvestigationError(ValueError):
    """Selection or required evidence cannot be resolved without ambiguity."""


SCHEMA_VERSION = 1
EXPORT_POLICY_VERSION = 1
# These are presentation schemas, not security predicates. Never export an
# arbitrary nested evidence dictionary, even when a caller bypasses the loader.
STATEMENT = {"effect": str, "conditional": bool, "actions": [str], "resources": [str],
             "not_actions": bool, "not_resources": bool}
EVIDENCE_FIELDS = {
    "AWSH-LAMBDA-001": {"urls": [{"arn": str, "auth": str}]},
    "AWSH-LAMBDA-002": {"role_policies": [str]},
    "AWSH-EC2-004": {"metadata": {"endpoint": str, "tokens": str}},
    "AWSH-EC2-005": {"addresses": [str]},
    "AWSH-IAM-001": {"attached": [str]},
    "AWSH-IAM-002": {"statements": [STATEMENT]},
    "AWSH-IAM-003": {"statements": [STATEMENT]},
    "AWSH-IAM-007": {"identity_profile": {"owner": bool, "service_linked": bool}},
    "AWSH-IAM-009": {"identity_usage": {"created_days": int, "last_used_days": (int, type(None)),
                                             "status": str}, "review_threshold_days": int},
}
FATAL_GAPS = frozenset({
    "RESOURCE_SCOPE_MISMATCH", "ROLE_SCOPE_MISMATCH", "UNVALIDATED_RESOURCE_LOCATOR",
    "AMBIGUOUS_RESOURCE_IDENTITY", "CONFLICTING_RESOURCE_ARN", "LAMBDA_URL_IDENTITY_MISMATCH",
    "EXECUTION_ROLE_BINDING_CONFLICT", "SUPPORTING_FINDING_UNAVAILABLE", "SUPPORTING_RELATIONSHIP_UNAVAILABLE",
})
# Export policy only: exact labels from registered collectors/evaluation and
# historical evidence. These sets neither authorize AWS calls nor validate the
# source snapshot. Keep casing and compound diagnostic labels intact.
COVERAGE_OPERATIONS = {
    "iam": frozenset({
        "GetAccountAuthorizationDetails", "AuthorizationDetails", "PolicyNormalization",
        "ConsoleMFA", "GetLoginProfile", "ListMFADevices", "ListAccessKeys", "GetAccessKeyLastUsed",
        "IdentityProfile", "RoleTrust", "RoleLastUsed", "IdentityManagedPolicy", "IdentityPolicyContext",
        "IdentityBinding", "IdentityBindings", "IdentityEvents", "IdentityAnalyzers",
        "GetRole", "GetRolePolicy", "GetPolicy", "GetPolicyVersion", "ListRoleTags", "ListUserTags",
        "ListAttachedRolePolicies", "GetInstanceProfile",
    }),
    "lambda": frozenset({
        "Region", "ListFunctions", "LambdaMetadata", "ListFunctionUrlConfigs", "ListAttachedRolePolicies",
        "ManagedRuntime (images/unknown runtimes not scanned)",
    }),
    "ec2": frozenset({
        "Region", "EC2Client", "describe_security_groups", "describe_instances", "describe_volumes",
        "describe_instances.metadata", "describe_instances.addresses",
        "DescribeSecurityGroups", "DescribeInstances", "DescribeVolumes",
    }),
    "bedrock": frozenset({
        "Region", "ListAgents", "GetAgent", "GetModelInvocationLoggingConfiguration", "RequiredCollection",
    }),
}
EVALUATION_OPERATIONS = frozenset({"RequiredFact", "RuleEvaluation", "CheckSelection", "ResourceSelection"})
RELATIONSHIP_OPERATIONS = {
    ("iam", "identity_bindings", "lambda"): frozenset({"GetRole", "ListFunctions"}),
    ("iam", "identity_bindings", "ec2"): frozenset({"GetRole", "DescribeInstances", "GetInstanceProfile"}),
    ("iam", "identity_bindings", "bedrock"): frozenset({"GetRole", "ListAgents", "GetAgent"}),
    ("iam", "identity_bindings", "agentcore"): frozenset({"GetRole", "ListAgentRuntimes", "GetAgentRuntime"}),
    ("bedrock", "execution_role_arn", "bedrock"): frozenset({"GetAgent"}),
}


def _operation(value: object, gaps: set[str], allowed: frozenset[str]) -> str | None:
    """Preserve stored nulls; export only an operation recognized in context."""
    if value is None or isinstance(value, str) and value in allowed:
        return value
    gaps.add("PROVENANCE_FIELD_UNAVAILABLE")
    return None


def _relationship_evidence(edge: dict, gaps: set[str]) -> dict:
    projected = []
    for evidence in edge["evidence"]:
        context = (evidence["service"], evidence["fact"], edge["source"]["service"])
        if context not in RELATIONSHIP_OPERATIONS:
            gaps.add("PROVENANCE_FIELD_UNAVAILABLE")
            projected.append({"service": None, "fact": None, "operation": None})
        else:
            projected.append({"service": evidence["service"], "fact": evidence["fact"],
                              "operation": _operation(evidence["operation"], gaps, RELATIONSHIP_OPERATIONS[context])})
    return {"source": deepcopy(edge["source"]), "type": edge["type"], "target": deepcopy(edge["target"]),
            "evidence": _evidence(projected)}


def _project(value: object, schema: object) -> object:
    if isinstance(schema, dict) and isinstance(value, dict) and schema.keys() <= value.keys():
        return {key: _project(value[key], schema[key]) for key in sorted(schema)}
    if isinstance(schema, list) and isinstance(value, list):
        return _evidence([_project(item, schema[0]) for item in value])
    if isinstance(schema, type) and type(value) is schema:
        return value
    if isinstance(schema, tuple) and type(value) in schema:
        return value
    raise InvestigationError("SUPPORTING_EVIDENCE_INVALID")


def _observation(snapshot: Snapshot, report) -> _Observation:
    """Index this exact evaluation for the existing M1 locator diagnostics."""
    resources, locators, findings = {}, {}, {}
    for collection in snapshot.services.values():
        for resource in collection.resources:
            key = resource_ref(resource).logical_key
            resources.setdefault(key, []).append(resource)
            if resource.resource_arn is not None:
                locators.setdefault(resource.resource_arn, set()).add(key)
    for finding in report.findings:
        data = finding.to_dict()
        findings.setdefault(_finding_key(data), []).append(data)
    edges = {_edge_key(data): data for edge in normalize_relationships(snapshot.relationships, snapshot.services)
             for data in (relationship_to_dict(edge),)}
    return _Observation(snapshot, report, {}, resources, locators, edges, findings)


def _validate_selection(lead: dict) -> None:
    rule = next((rule for rule in CORRELATION_RULES if rule.pattern_id == lead["pattern_id"]), None)
    if rule is None or lead["priority"] != rule.priority.value or lead["title"] != rule.title:
        raise InvestigationError("INCONSISTENT_LEAD_IDENTITY")
    subjects = sorted({_resource_key(ref) for ref in lead["subjects"]})
    if not subjects:
        raise InvestigationError("INCONSISTENT_LEAD_IDENTITY")
    identity = {"pattern_id": rule.pattern_id, "subjects": [list(key) for key in subjects]}
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True).encode("utf-8")).hexdigest()
    if lead["lead_id"] != f"{rule.pattern_id}:{digest}":
        raise InvestigationError("INCONSISTENT_LEAD_IDENTITY")
    identifiers = {ref["check_id"] for ref in lead["findings"]}
    required = LOCAL_PREDICATES[rule.pattern_id]
    if rule.pattern_id == "AI-WORKLOAD-BROAD-EXECUTION-ROLE":
        required = (BROAD,)
    # EC2's local predicates have an additional broad-role support requirement.
    if rule.pattern_id == "PUBLIC-EC2-IMDSV1-BROAD-ROLE":
        required = (*required, BROAD)
    if any(not identifiers.intersection(group) for group in required):
        raise InvestigationError("REQUIRED_FINDING_UNAVAILABLE")
    if rule.requires_relationships and not lead["relationships"]:
        raise InvestigationError("REQUIRED_RELATIONSHIP_UNAVAILABLE")
    for edge in lead["relationships"]:
        source, target = _resource_key(edge["source"]), _resource_key(edge["target"])
        incoming = rule.pattern_id == "UNOWNED-BROAD-IAM-WORKLOAD-ROLE"
        if (edge["type"] != "RUNS_AS" or (target if incoming else source) not in subjects
                or edge["target"]["service"] != "iam" or edge["target"]["resource_type"] != "role"):
            raise InvestigationError("INCONSISTENT_SUPPORTING_RELATIONSHIP")


def _coverage(report, resources: list[dict], gaps: set[str]) -> list[dict]:
    """Relevant service coverage, never raw SDK/collector error messages."""
    relevant = {}
    for ref in resources:
        relevant.setdefault(ref["service"], set()).add(ref["resource_id"])
    result = []
    for row in sorted(report.coverage, key=lambda item: item["service"]):
        if row["service"] not in relevant:
            continue
        allowed = COVERAGE_OPERATIONS.get(row["service"], frozenset()) | EVALUATION_OPERATIONS
        if row["service"] == "iam":
            # This collector persists a scoped diagnostic, not an SDK operation.
            # Enumerate exact labels from known families and relevant saved
            # regions; do not accept arbitrary prefix/suffix payloads.
            regions = {report.metadata["region"], *(ref["region"] for ref in resources)}
            allowed |= frozenset(f"IdentityBindings:{service}:{region}"
                                 for service in ("lambda", "ec2", "bedrock", "agentcore")
                                 for region in regions if isinstance(region, str)
                                 and re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}", region))
        issues = []
        for issue in row["issues"]:
            if issue.get("resource_id") not in {None, *relevant[row["service"]]}:
                continue
            text = issue.get("message", "").lower()
            reason = ("ACCESS_DENIED" if "accessdenied" in text or "access denied" in text else
                      "THROTTLED" if "throttl" in text else "COLLECTION_OR_EVALUATION_INCOMPLETE")
            issues.append({"resource_id": issue.get("resource_id"), "operation": _operation(issue["operation"], gaps, allowed),
                           "reason_code": reason})
        result.append({"service": row["service"], "account_id": row["account_id"],
                       "region": None if row["service"] == "iam" else report.metadata["region"],
                       "status": row["status"],
                       "scope": "SERVICE_COVERAGE_NOT_PER_LEAD_CHECK_COMPLETENESS",
                       "issues": sorted(issues, key=lambda item: json.dumps(item, sort_keys=True))})
    return result


def build_evidence_pack(snapshot: Snapshot, lead_id: str) -> dict:
    """Consume validated facts; evaluate and correlate once, never contact AWS."""
    if not isinstance(lead_id, str) or re.fullmatch(r"[A-Z0-9-]+:[0-9a-f]{64}", lead_id) is None:
        raise InvestigationError("FULL_EXACT_LEAD_ID_REQUIRED")
    try:
        report = evaluate_snapshot(snapshot)
    except (SnapshotError, RelationshipError) as error:
        raise InvestigationError("SOURCE_EVIDENCE_INVALID") from error
    document = investigation_leads(snapshot, report=report)
    matches = [lead for lead in document["leads"] if lead["lead_id"] == lead_id]
    if len(matches) != 1:
        raise InvestigationError("LEAD_NOT_FOUND" if not matches else "AMBIGUOUS_LEAD_ID")
    lead = matches[0]
    _validate_selection(lead)
    observation = _observation(snapshot, report)
    support = _support(observation, lead)
    fatal = sorted(FATAL_GAPS.intersection(support["gaps"]))
    if fatal:
        raise InvestigationError(", ".join(fatal))
    findings = []
    for key in sorted(support["findings"]):
        finding = observation.findings[key][0]
        if key[0] not in EVIDENCE_FIELDS:
            raise InvestigationError("UNSUPPORTED_SUPPORTING_CHECK")
        identity = next(iter(observation.locators[finding["resource_arn"]]))
        ref = resource_ref(observation.resources[identity][0])
        findings.append({"check_id": key[0], "title": finding["title"], "severity": finding["severity"],
                         "resource": {"account_id": ref.account_id, "region": ref.region, "service": ref.service,
                                      "resource_type": ref.resource_type, "resource_id": ref.resource_id,
                                      "resource_arn": ref.resource_arn},
                         "evidence": _project(finding["evidence"], EVIDENCE_FIELDS[key[0]]),
                         "references": sorted(set(finding["references"])),
                         "provenance": {"scan_id": snapshot.metadata.scan_id, "check_id": key[0],
                                        "api_operation": None}})
    gaps = set(support["gaps"])
    relationships = [_relationship_evidence(observation.edges[key], gaps) for key in sorted(support["edges"])]
    resources = [*lead["subjects"], *lead["related_resources"]]
    coverage = _coverage(report, resources, gaps)
    limitations = set(gaps)
    # Missing optional API provenance is honest uncertainty, not a failure of
    # the positive predicate. Required normalized evidence is already resolved.
    limitations.update({"API_OPERATION_UNAVAILABLE", "EFFECTIVE_PERMISSIONS_NOT_EVALUATED",
                        "RELATIONSHIP_INVENTORY_NOT_EXHAUSTIVE", "IAM_INCARNATION_CONTINUITY_UNAVAILABLE"})
    partial = bool(gaps)
    metadata = snapshot.metadata
    return {"kind": "investigation-evidence-pack", "schema_version": SCHEMA_VERSION,
            "export_policy_version": EXPORT_POLICY_VERSION, "status": "PARTIAL" if partial else "COMPLETE",
            "status_scope": "SUPPORTING_EVIDENCE_EXPORT_NOT_SECURITY_PASS",
            "lead": {key: deepcopy(lead[key]) for key in (
                "lead_id", "pattern_id", "priority", "title", "subjects", "related_resources", "why_it_matters")},
            "findings": findings, "relationships": relationships,
            "source_snapshot": {"scan_id": metadata.scan_id, "account_id": metadata.account_id,
                                "region": metadata.region, "schema_version": snapshot.schema_version,
                                "collection_started_at": metadata.started_at.isoformat(),
                                "producer_version": metadata.version,
                                "supports_relationships": snapshot.supports_relationships},
            "evaluation": {"evaluator_version": __version__, "correlation_version": __version__,
                           "locator_policy_version": POLICY_VERSION,
                           "check_ids": sorted({finding["check_id"] for finding in findings}),
                           "explanation_source": "EXISTING_REGISTERED_LEAD_RULE"},
            "statements": {key: sorted((dict(item) for item in lead[key]), key=lambda item: item["code"])
                           for key in ("observed", "unknown", "not_proven")},
            "coverage": coverage, "limitations": sorted(limitations),
            "manual_steps": [lead["next_step"]],
            "disclaimer": "Minimized, not anonymous. Observations do not prove compromise, an attack path, "
                          "effective permissions, invocation, production traffic or remediation."}


def render_evidence_json(pack: dict) -> str:
    return json.dumps(pack, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def render_evidence_html(pack: dict) -> str:
    environment = Environment(loader=PackageLoader("awsherlock", "templates"),
                              autoescape=select_autoescape(default=True), undefined=StrictUndefined)
    links = {reference: _safe_https_url(reference)
             for finding in pack["findings"] for reference in finding["references"]}
    return environment.get_template("investigation.html").render(pack=pack, links=links,
        evidence_text={index: json.dumps(finding["evidence"], sort_keys=True, indent=2, ensure_ascii=False)
                       for index, finding in enumerate(pack["findings"])}) + "\n"
