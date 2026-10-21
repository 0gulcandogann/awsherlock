"""Evidence-aware adaptation of existing Leads, with no new security predicates.

Policy 1 prioritizes configuration indicators, never impact or confidence.
Missing evidence does not reduce the score; identity conflicts block it.
"""

import json

from awsherlock.correlation import CorrelationError, FindingRef, RelationshipRef
from awsherlock.evaluation import Report, evaluate_snapshot
from awsherlock.coverage_intelligence import coverage_issue_rows
from awsherlock.investigation import (
    FATAL_GAPS,
    InvestigationError,
    _observation,
    assess_lead_support,
)
from awsherlock.investigation_models import (
    CoverageGate,
    EvidenceRef,
    Investigation,
    InvestigationAction,
    InvestigationCondition,
    InvestigationResult,
    PriorityFactor,
)
from awsherlock.leads import investigation_leads
from awsherlock.models import RelationshipType, ResourceRef
from awsherlock.snapshot import Snapshot

# Exact existing observed-statement codes and their supporting predicates.
# Relationship observations cite edges, not a broad policy Finding.
OBSERVED_CHECKS = {
    "LAMBDA_URL_WITHOUT_IAM_AUTH": frozenset({"AWSH-LAMBDA-001"}),
    "LAMBDA_BROAD_MANAGED_ROLE_POLICY": frozenset({"AWSH-LAMBDA-002"}),
    "EC2_PUBLIC_ADDRESS": frozenset({"AWSH-EC2-005"}),
    "EC2_IMDSV1_ALLOWED": frozenset({"AWSH-EC2-004"}),
    "IAM_BROAD_PERMISSION_FINDING": frozenset({"AWSH-IAM-001", "AWSH-IAM-002", "AWSH-IAM-003"}),
    "IAM_ROLE_OWNER_MISSING": frozenset({"AWSH-IAM-007"}),
    "IAM_ROLE_STALE_USAGE": frozenset({"AWSH-IAM-009"}),
}
RELATIONSHIP_STATEMENTS = frozenset(
    {
        "EC2_RUNS_AS_IAM_ROLE",
        "WORKLOAD_RUNS_AS_IAM_ROLE",
        "AI_WORKLOAD_RUNS_AS_IAM_ROLE",
    }
)
# Each independently supported indicator category contributes once. Multiple
# overlapping IAM checks or duplicate edges must not inflate the assessment.
FACTOR_POLICY = (
    (
        "CONFIGURATION_EXPOSURE",
        2,
        frozenset({"AWSH-LAMBDA-001", "AWSH-EC2-005"}),
        "Public addressing or URL authentication configuration warrants exposure review; reachability is unknown.",
    ),
    (
        "BROAD_PERMISSION_INDICATOR",
        2,
        frozenset({"AWSH-IAM-001", "AWSH-IAM-002", "AWSH-IAM-003", "AWSH-LAMBDA-002"}),
        "Broad policy configuration warrants permission review; effective permissions are unknown.",
    ),
    (
        "METADATA_WEAKNESS",
        1,
        frozenset({"AWSH-EC2-004"}),
        "IMDSv1 is permitted; application request paths and credential access remain unknown.",
    ),
    (
        "GOVERNANCE_OR_USAGE",
        1,
        frozenset({"AWSH-IAM-007", "AWSH-IAM-009"}),
        "Missing owner metadata or recorded stale usage warrants a business-need review.",
    ),
)
PRIORITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNASSESSED": 3}


def _gates(
    rows: list[dict], *, account_id: str, region: str | None, codes: tuple[str, ...] = ()
) -> tuple[CoverageGate, ...]:
    values = [CoverageGate(code=code, account_id=account_id, region=region) for code in codes]
    for row in rows:
        if row["status"] != "COMPLETE":
            values.append(
                CoverageGate(
                    code="SERVICE_COVERAGE_INCOMPLETE",
                    account_id=row["account_id"],
                    region=row["region"],
                    service=row["service"],
                    status=row["status"],
                )
            )
        for issue in row["issues"]:
            values.append(
                CoverageGate(
                    code="EVIDENCE_READ_INCOMPLETE",
                    account_id=row["account_id"],
                    region=row["region"],
                    service=row["service"],
                    status=row["status"],
                    reason_code=issue["reason_code"],
                    operation=issue["operation"],
                    resource_id=issue["resource_id"],
                )
            )
    unique = {value.id: value for value in values}
    return tuple(unique[key] for key in sorted(unique))


def _factors(
    findings: tuple[FindingRef, ...], relationships: tuple[RelationshipRef, ...]
) -> tuple[PriorityFactor, ...]:
    factors = []
    for code, points, checks, explanation in FACTOR_POLICY:
        evidence = tuple(
            EvidenceRef.from_reference(ref) for ref in findings if ref.check_id in checks
        )
        if evidence:
            factors.append(
                PriorityFactor(code=code, points=points, explanation=explanation, evidence=evidence)
            )
    evidence = tuple(
        EvidenceRef.from_reference(ref)
        for ref in relationships
        if ref.relationship_type is RelationshipType.RUNS_AS
    )
    if evidence:
        factors.append(
            PriorityFactor(
                code="OBSERVED_WORKLOAD_BINDING",
                points=1,
                explanation="A positive workload-role configuration binding connects the indicators; credential access is unknown.",
                evidence=evidence,
            )
        )
    return tuple(factors)


def _adapt(lead: dict, observation) -> Investigation:
    findings = tuple(FindingRef(**ref) for ref in lead["findings"])
    relationships = tuple(
        RelationshipRef(
            source=ResourceRef(**ref["source"]),
            relationship_type=RelationshipType(ref["type"]),
            target=ResourceRef(**ref["target"]),
        )
        for ref in lead["relationships"]
    )
    resources = {
        ref.logical_key: ref
        for ref in (
            *(ResourceRef(**item) for item in [*lead["subjects"], *lead["related_resources"]]),
            *(ref for edge in relationships for ref in (edge.source, edge.target)),
        )
    }
    metadata = observation.snapshot.metadata
    rows, codes = assess_lead_support(observation, lead)
    gaps = _gates(rows, account_id=metadata.account_id, region=metadata.region, codes=codes)
    blocked = bool(FATAL_GAPS.intersection(codes))
    observed = []
    for statement in lead["observed"]:
        code = statement["code"]
        if code in OBSERVED_CHECKS:
            evidence = tuple(
                EvidenceRef.from_reference(ref)
                for ref in findings
                if ref.check_id in OBSERVED_CHECKS[code]
            )
        elif code in RELATIONSHIP_STATEMENTS:
            evidence = tuple(EvidenceRef.from_reference(ref) for ref in relationships)
        else:
            # An extension needs an explicit evidence mapping before its prose
            # can be promoted to an observed fact.
            raise InvestigationError("UNMAPPED_OBSERVED_CONDITION")
        if not evidence:
            raise InvestigationError("OBSERVED_CONDITION_WITHOUT_SUPPORT")
        observed.append(
            InvestigationCondition(code=code, text=statement["text"], evidence=evidence)
        )
    all_evidence = tuple(EvidenceRef.from_reference(ref) for ref in (*findings, *relationships))
    unknown = {
        item["code"]: InvestigationCondition(code=item["code"], text=item["text"])
        for item in [*lead["unknown"], *lead["not_proven"]]
    }
    unknown["ASSET_CRITICALITY_UNKNOWN"] = InvestigationCondition(
        code="ASSET_CRITICALITY_UNKNOWN",
        text="No authoritative asset criticality is available; production or business impact is not assumed.",
    )
    unknown["RELATIONSHIP_INVENTORY_NOT_EXHAUSTIVE"] = InvestigationCondition(
        code="RELATIONSHIP_INVENTORY_NOT_EXHAUSTIVE",
        text="Positive relationships do not establish exhaustive relationship inventory.",
    )
    for gap in gaps:
        unknown[gap.id] = InvestigationCondition(
            code=gap.code,
            text="Evidence limitation: "
            + gap.code
            + (" / " + gap.reason_code if gap.reason_code else ""),
            evidence=(EvidenceRef(kind="COVERAGE", id=gap.id),),
        )
    if blocked:
        for condition in observed:
            unknown[condition.code] = InvestigationCondition(
                code=condition.code,
                text="Unverified candidate condition because supporting identity is inconsistent: "
                + condition.text,
                evidence=condition.evidence,
            )
        observed, inferred, factors = [], (), ()
        score, priority, status = None, "UNASSESSED", "BLOCKED"
        priority_explanation = "Priority blocked by inconsistent supporting identity or evidence. Review coverage gaps first."
    else:
        inferred = (
            InvestigationCondition(
                code="CORRELATED_CONFIGURATION_REQUIRES_REVIEW",
                text=lead["why_it_matters"],
                evidence=all_evidence,
                assumptions=(
                    "Saved normalized configuration describes the collection observation, not current state.",
                    "Exact logical resource identities connect the indicators; effective access and exploitability are not established.",
                ),
            ),
        )
        factors = _factors(findings, relationships)
        score = sum(factor.points for factor in factors)
        priority = "HIGH" if score >= 5 else "MEDIUM" if score >= 2 else "LOW"
        status = "PROVISIONAL"
        priority_explanation = f"Indicator score {score}/7: " + "; ".join(
            f"{factor.code} +{factor.points}" for factor in factors
        ) + ". This is review urgency, not impact or confidence. Effective permissions, reachability and asset criticality " "remain unverified. Missing evidence never subtracts points." + (
            " Supporting coverage is limited; review the coverage gaps." if gaps else ""
        )
    actions = [InvestigationAction(code="REVIEW_CONFIGURATION", text=lead["next_step"])]
    if gaps:
        actions.insert(
            0,
            InvestigationAction(
                code="VERIFY_EVIDENCE_GAPS",
                text="Review recorded coverage gaps and obtain authorized read-only evidence before concluding safety or resolution.",
            ),
        )
    return Investigation(
        id="investigation:" + lead["lead_id"],
        lead_id=lead["lead_id"],
        pattern_id=lead["pattern_id"],
        title=lead["title"],
        account_id=metadata.account_id,
        region=lead["subjects"][0]["region"],
        resources=tuple(resources[key] for key in sorted(resources)),
        supporting_findings=findings,
        supporting_relationships=relationships,
        observed=tuple(observed),
        inferred=inferred,
        unknown=tuple(unknown[key] for key in sorted(unknown)),
        coverage_gaps=gaps,
        priority=priority,
        priority_status=status,
        priority_score=score,
        priority_factors=factors,
        priority_explanation=priority_explanation,
        explanation=(
            lead["why_it_matters"]
            if not blocked
            else "Candidate correlation requires evidence identity review."
        ),
        recommended_actions=tuple(actions),
    )


def build_investigations(
    snapshot: Snapshot, *, report: Report | None = None, leads: dict | None = None
) -> InvestigationResult:
    """Derive once per scope. Supplied report/leads must be its exact evaluation.

    An optional report preserves selectors and suppressions. Suppressions never
    remove supporting Findings. No time, credentials, clients or network needed.
    """
    report = evaluate_snapshot(snapshot) if report is None else report
    if any(
        report.metadata.get(key) != getattr(snapshot.metadata, key)
        for key in ("scan_id", "account_id", "region")
    ):
        raise CorrelationError("Investigation report scope does not match source snapshot")
    document = investigation_leads(snapshot, report=report) if leads is None else leads
    observation = _observation(snapshot, report)
    investigations = tuple(
        sorted(
            (_adapt(lead, observation) for lead in document["leads"]),
            key=lambda item: (PRIORITY_ORDER[item.priority], item.pattern_id, item.id),
        )
    )
    # Scope-wide gaps include services that cannot participate in a Lead. Reuse
    # Coverage Intelligence's full registry allowlists, rather than the narrower
    # historical Evidence Pack projection. Raw messages never leave this boundary.
    rows = []
    for row in report.coverage:
        region = None if row["service"] in {"iam", "s3"} else snapshot.metadata.region
        issues = coverage_issue_rows(row["account_id"], region, row["service"], row["issues"])
        rows.append(
            {
                "account_id": row["account_id"],
                "region": region,
                "service": row["service"],
                "status": row["status"],
                "issues": issues,
            }
        )
    codes: set[str] = set()
    if not snapshot.supports_relationships:
        codes.add("RELATIONSHIPS_UNSUPPORTED")
    gaps = _gates(
        rows,
        account_id=snapshot.metadata.account_id,
        region=snapshot.metadata.region,
        codes=tuple(sorted(codes)),
    )
    return InvestigationResult(
        account_id=snapshot.metadata.account_id,
        region=snapshot.metadata.region,
        investigations=investigations,
        coverage_gaps=gaps,
        incomplete=report.incomplete
        or bool(gaps)
        or any(item.coverage_gaps for item in investigations),
    )


def render_investigations_json(result: InvestigationResult) -> str:
    return (
        json.dumps(result.to_dict(), sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
        + "\n"
    )
