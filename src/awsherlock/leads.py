"""Bounded, finding-level investigation hints; never an attack-path model."""

import json

from awsherlock.evaluation import evaluate_snapshot
from awsherlock.snapshot import Snapshot


LAMBDA_PAIR = frozenset({"AWSH-LAMBDA-001", "AWSH-LAMBDA-002"})


def investigation_leads(snapshot: Snapshot) -> dict:
    report = evaluate_snapshot(snapshot)
    grouped: dict[tuple[str, str, str], set[str]] = {}
    for finding in report.findings:
        if finding.id in LAMBDA_PAIR:
            key = (finding.account_id, finding.region or "", finding.resource_id)
            grouped.setdefault(key, set()).add(finding.id)
    leads = []
    for (account_id, region, resource_id), identifiers in sorted(grouped.items()):
        if identifiers == LAMBDA_PAIR:
            leads.append({"pattern_id": "LAMBDA-URL-BROAD-ROLE", "account_id": account_id,
                          "region": region or None, "resource_id": resource_id,
                          "indicator_check_ids": sorted(identifiers),
                          "why_review": "A Function URL without IAM authentication and a broad AWS-managed execution-role policy were both reported for this function.",
                          "next_step": "Review URL resource policy and network reachability, then inspect effective role permissions, boundaries and denies.",
                          "limit": "This does not prove anonymous reachability, effective access, exploitability or an attack path."})
    return {"schema_version": 1, "kind": "investigation-leads",
            "account_id": snapshot.metadata.account_id, "region": snapshot.metadata.region,
            "coverage": report.coverage, "incomplete": report.incomplete,
            "leads": leads, "summary": {"leads": len(leads)}}


def render_leads_json(document: dict) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
