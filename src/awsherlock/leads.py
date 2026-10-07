"""Deterministic offline correlations; never an attack-path model."""

import json

from awsherlock.correlation import (
    CorrelationContext,
    CorrelationError,
    CorrelationRule,
    Lead,
    LeadPriority,
    LeadStatement,
    build_correlation_context,
    finding_ref,
    finding_resource_key,
    lead_to_dict,
    merge_leads,
    relationship_ref,
    resource_ref,
    validate_correlation_rules,
)
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.models import RelationshipType
from awsherlock.snapshot import Snapshot


BROAD_IAM_CHECKS = frozenset({"AWSH-IAM-001", "AWSH-IAM-002", "AWSH-IAM-003"})


def _statements(entries: tuple[tuple[str, str], ...]) -> tuple[LeadStatement, ...]:
    return tuple(LeadStatement(code=code, text=text) for code, text in entries)


def _by_resource(context: CorrelationContext, check_id: str) -> dict[tuple, tuple]:
    grouped = {}
    for finding in context.findings_by_check.get(check_id, ()):
        grouped.setdefault(finding_resource_key(finding), []).append(finding)
    return {key: tuple(value) for key, value in grouped.items()}


def _findings_for_reference(context: CorrelationContext, findings: tuple, reference) -> tuple:
    key = (reference.account_id, reference.region or "", reference.service, reference.resource_id)
    same_named = context.resources_by_key.get(key, ())
    return tuple(finding for finding in findings
                 if (finding.resource_arn == reference.resource_arn
                     if reference.resource_arn is not None else
                     finding.resource_arn is None and len(same_named) == 1
                     and same_named[0].resource_type == reference.resource_type))


def _broad_findings(context: CorrelationContext, reference) -> tuple:
    key = (reference.account_id, reference.region or "", reference.service, reference.resource_id)
    findings = tuple(finding for finding in context.findings_by_resource.get(key, ())
                     if finding.id in BROAD_IAM_CHECKS)
    return _findings_for_reference(context, findings, reference)


def _ordered_coverage(coverage: list[dict]) -> list[dict]:
    ordered = []
    for entry in coverage:
        item = dict(entry)
        item["issues"] = sorted(
            (dict(issue) for issue in entry.get("issues", [])),
            key=lambda issue: (
                issue.get("resource_id") or "",
                issue.get("operation") or "",
                issue.get("message") or "",
            ),
        )
        ordered.append(item)
    return sorted(ordered, key=lambda item: (item.get("account_id") or "", item.get("service") or ""))


def _lambda_url_broad_role(context: CorrelationContext) -> tuple[Lead, ...]:
    url_findings = _by_resource(context, "AWSH-LAMBDA-001")
    role_findings = _by_resource(context, "AWSH-LAMBDA-002")
    candidates = []
    for key in sorted(url_findings.keys() & role_findings.keys()):
        exemplar = url_findings[key][0]
        resource = context.resource_for(key, resource_type="function", resource_arn=exemplar.resource_arn)
        if resource is None or resource.service != "lambda" or resource.resource_type != "function":
            continue
        subject = resource_ref(resource)
        edges = ()
        if context.snapshot.supports_relationships:
            edges = tuple(edge for edge in context.relationships_from.get(subject.logical_key, ())
                          if edge.relationship_type is RelationshipType.RUNS_AS
                          and edge.target.service == "iam" and edge.target.resource_type == "role")
        candidates.append(Lead(
            pattern_id="LAMBDA-URL-BROAD-ROLE",
            subjects=(subject,),
            title="Lambda URL and broad execution-role policy signals are related",
            priority=LeadPriority.HIGH,
            related_resources=tuple(edge.target for edge in edges),
            finding_refs=tuple(finding_ref(item) for item in url_findings[key] + role_findings[key]),
            relationship_refs=tuple(relationship_ref(edge) for edge in edges),
            observed=_statements((
                ("LAMBDA_URL_WITHOUT_IAM_AUTH", "The Lambda Function URL does not require IAM authentication."),
                ("LAMBDA_BROAD_MANAGED_ROLE_POLICY", "The Lambda execution role has a broad AWS-managed policy signal."),
            )),
            unknown=_statements((
                ("EFFECTIVE_IAM_PERMISSIONS_NOT_EVALUATED", "Effective IAM permissions were not evaluated."),
                ("NETWORK_REACHABILITY_NOT_EVALUATED", "Network reachability was not evaluated."),
            )),
            not_proven=_statements((
                ("ANONYMOUS_REACHABILITY_NOT_PROVEN", "Anonymous reachability is not proven."),
                ("ATTACK_PATH_NOT_PROVEN", "A confirmed attack path is not proven."),
                ("EXPLOITABILITY_NOT_PROVEN", "Exploitability is not proven."),
            )),
            why_it_matters="A Function URL configured without IAM authentication and broad execution-role policy signals are worth reviewing together.",
            next_step="Review the Function URL resource policy and reachability, then inspect role boundaries, denies, and effective permissions.",
        ))
    return tuple(candidates)


def _public_ec2_imdsv1_broad_role(context: CorrelationContext) -> tuple[Lead, ...]:
    metadata_findings = _by_resource(context, "AWSH-EC2-004")
    public_findings = _by_resource(context, "AWSH-EC2-005")
    candidates = []
    for key in sorted(metadata_findings.keys() & public_findings.keys()):
        exemplar = metadata_findings[key][0]
        resource = context.resource_for(key, resource_type="instance", resource_arn=exemplar.resource_arn)
        if resource is None or resource.service != "ec2" or resource.resource_type != "instance":
            continue
        subject = resource_ref(resource)
        for edge in context.relationships_from.get(subject.logical_key, ()):
            if (edge.relationship_type is not RelationshipType.RUNS_AS
                    or edge.target.service != "iam" or edge.target.resource_type != "role"):
                continue
            broad = _broad_findings(context, edge.target)
            if not broad:
                continue
            candidates.append(Lead(
                pattern_id="PUBLIC-EC2-IMDSV1-BROAD-ROLE",
                subjects=(subject,),
                title="Public EC2, IMDSv1, and broad role-permission signals are related",
                priority=LeadPriority.HIGH,
                related_resources=(edge.target,),
                finding_refs=tuple(finding_ref(item) for item in
                                   metadata_findings[key] + public_findings[key] + broad),
                relationship_refs=(relationship_ref(edge),),
                observed=_statements((
                    ("EC2_PUBLIC_ADDRESS", "The EC2 instance has public IP addressing."),
                    ("EC2_IMDSV1_ALLOWED", "The EC2 instance permits IMDSv1."),
                    ("EC2_RUNS_AS_IAM_ROLE", "The EC2 instance is observed running as an IAM role."),
                    ("IAM_BROAD_PERMISSION_FINDING", "The exact target role has a broad IAM permission finding."),
                )),
                unknown=_statements((
                    ("APPLICATION_REQUEST_PATH_NOT_EVALUATED", "An application or SSRF request path was not evaluated."),
                    ("EFFECTIVE_IAM_PERMISSIONS_NOT_EVALUATED", "Effective IAM permissions were not evaluated."),
                    ("NETWORK_REACHABILITY_NOT_EVALUATED", "Effective network reachability was not evaluated."),
                )),
                not_proven=_statements((
                    ("ATTACK_PATH_NOT_PROVEN", "A confirmed attack path is not proven."),
                    ("COMPROMISE_NOT_PROVEN", "Compromise is not proven."),
                    ("CREDENTIAL_ACCESS_NOT_PROVEN", "Credential retrieval is not proven."),
                    ("EFFECTIVE_ACCESS_NOT_PROVEN", "Effective IAM access is not proven."),
                    ("EXPLOITABILITY_NOT_PROVEN", "Exploitability is not proven."),
                )),
                why_it_matters="Public addressing, weak metadata controls, and broad role signals on one workload warrant prioritized investigation.",
                next_step="Verify effective reachability and application request paths, then review IMDS controls and the role's effective permissions.",
            ))
    return tuple(candidates)


def _unowned_broad_workload_role(context: CorrelationContext) -> tuple[Lead, ...]:
    unowned = _by_resource(context, "AWSH-IAM-007")
    candidates = []
    for key in sorted(unowned):
        resource = context.resource_for(key, resource_type="role")
        if resource is None or resource.service != "iam" or resource.resource_type != "role":
            continue
        subject = resource_ref(resource)
        role_unowned = _findings_for_reference(context, unowned[key], subject)
        broad = _broad_findings(context, subject)
        if not role_unowned or not broad:
            continue
        edges = tuple(edge for edge in context.relationships_to.get(subject.logical_key, ())
                      if edge.relationship_type is RelationshipType.RUNS_AS)
        if not edges:
            continue
        candidates.append(Lead(
            pattern_id="UNOWNED-BROAD-IAM-WORKLOAD-ROLE",
            subjects=(subject,),
            title="Unowned workload role has broad IAM permission signals",
            priority=LeadPriority.MEDIUM,
            related_resources=tuple(edge.source for edge in edges),
            finding_refs=tuple(finding_ref(item) for item in role_unowned + broad),
            relationship_refs=tuple(relationship_ref(edge) for edge in edges),
            observed=_statements((
                ("IAM_ROLE_OWNER_MISSING", "Owner metadata is missing for the IAM role."),
                ("IAM_BROAD_PERMISSION_FINDING", "The IAM role has a broad permission finding."),
                ("WORKLOAD_RUNS_AS_IAM_ROLE", "One or more observed workloads run as the IAM role."),
            )),
            unknown=_statements((
                ("EFFECTIVE_IAM_PERMISSIONS_NOT_EVALUATED", "Effective IAM permissions were not evaluated."),
                ("EXCLUSIVE_NHI_STATUS_NOT_EVALUATED", "Exclusive non-human use of the role was not evaluated."),
            )),
            not_proven=_statements((
                ("COMPROMISE_NOT_PROVEN", "Compromise is not proven."),
                ("EXPLOITABILITY_NOT_PROVEN", "Exploitability is not proven."),
            )),
            why_it_matters="An unowned role with broad permission signals is actively associated with observed workloads.",
            next_step="Assign an accountable owner and review each workload association, policy boundary, deny, and effective permission.",
        ))
    return tuple(candidates)


def _stale_broad_role(context: CorrelationContext) -> tuple[Lead, ...]:
    stale = _by_resource(context, "AWSH-IAM-009")
    candidates = []
    for key in sorted(stale):
        resource = context.resource_for(key, resource_type="role")
        if resource is None or resource.service != "iam" or resource.resource_type != "role":
            continue
        subject = resource_ref(resource)
        role_stale = _findings_for_reference(context, stale[key], subject)
        broad = _broad_findings(context, subject)
        if not role_stale or not broad:
            continue
        candidates.append(Lead(
            pattern_id="STALE-BROAD-IAM-ROLE",
            subjects=(subject,),
            title="Stale IAM role has broad permission signals",
            priority=LeadPriority.MEDIUM,
            finding_refs=tuple(finding_ref(item) for item in role_stale + broad),
            observed=_statements((
                ("IAM_ROLE_STALE_USAGE", "The IAM role has a stale usage finding."),
                ("IAM_BROAD_PERMISSION_FINDING", "The IAM role has a broad permission finding."),
            )),
            unknown=_statements((
                ("EFFECTIVE_IAM_PERMISSIONS_NOT_EVALUATED", "Effective IAM permissions were not evaluated."),
                ("CURRENT_BUSINESS_NEED_NOT_EVALUATED", "Current business need for the role was not evaluated."),
            )),
            not_proven=_statements((
                ("COMPROMISE_NOT_PROVEN", "Compromise is not proven."),
                ("UNNECESSARY_ACCESS_NOT_PROVEN", "Unnecessary effective access is not proven."),
            )),
            why_it_matters="Stale-use and broad-permission signals on one role warrant an ownership and access review.",
            next_step="Confirm current ownership and business need, then inspect boundaries, denies, and effective permissions before retirement.",
        ))
    return tuple(candidates)


CORRELATION_RULES = (
    CorrelationRule(pattern_id="LAMBDA-URL-BROAD-ROLE",
                    title="Lambda URL and broad execution-role policy signals are related",
                    priority=LeadPriority.HIGH, requires_relationships=False,
                    correlate=_lambda_url_broad_role),
    CorrelationRule(pattern_id="PUBLIC-EC2-IMDSV1-BROAD-ROLE",
                    title="Public EC2, IMDSv1, and broad role-permission signals are related",
                    priority=LeadPriority.HIGH, requires_relationships=True,
                    correlate=_public_ec2_imdsv1_broad_role),
    CorrelationRule(pattern_id="UNOWNED-BROAD-IAM-WORKLOAD-ROLE",
                    title="Unowned workload role has broad IAM permission signals",
                    priority=LeadPriority.MEDIUM, requires_relationships=True,
                    correlate=_unowned_broad_workload_role),
    CorrelationRule(pattern_id="STALE-BROAD-IAM-ROLE",
                    title="Stale IAM role has broad permission signals",
                    priority=LeadPriority.MEDIUM, requires_relationships=False,
                    correlate=_stale_broad_role),
)
validate_correlation_rules(CORRELATION_RULES)


def investigation_leads(snapshot: Snapshot) -> dict:
    report = evaluate_snapshot(snapshot)
    context = build_correlation_context(snapshot, report.findings, report.coverage)
    candidates = []
    for rule in CORRELATION_RULES:
        if rule.requires_relationships and not snapshot.supports_relationships:
            continue
        try:
            produced = rule.correlate(context)
            if any(lead.pattern_id != rule.pattern_id or lead.title != rule.title
                   or lead.priority is not rule.priority for lead in produced):
                raise CorrelationError("Correlation rule output conflicts with registry metadata")
            candidates.extend(produced)
        except CorrelationError:
            raise
        except Exception as error:
            raise CorrelationError(f"Correlation rule {rule.pattern_id} failed") from error
    leads = merge_leads(candidates)
    priority_counts = {priority.value: sum(lead.priority is priority for lead in leads)
                       for priority in LeadPriority}
    return {"schema_version": 2, "kind": "investigation-leads",
            "account_id": snapshot.metadata.account_id, "region": snapshot.metadata.region,
            "source_snapshot": {"scan_id": snapshot.metadata.scan_id,
                                "schema_version": snapshot.schema_version,
                                "supports_relationships": snapshot.supports_relationships},
            "coverage": _ordered_coverage(report.coverage), "incomplete": report.incomplete,
            "leads": [lead_to_dict(lead) for lead in leads],
            "summary": {"leads": len(leads), "priority": priority_counts}}


def render_leads_json(document: dict) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
