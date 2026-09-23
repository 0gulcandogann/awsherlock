"""Present declared, configured and observed evidence without AI inference."""


def identity_summary(resource, excluded: bool = False) -> dict:
    data = resource.data
    approval = data.get("identity_approval", {})
    profile = data.get("identity_profile", {})
    bindings = data.get("identity_bindings", [])
    native = any(binding["service"] in {"bedrock", "agentcore"} for binding in bindings)
    declared = approval.get("declared_kind", "unknown")
    source = "inventory"
    if declared == "unknown":
        declared = profile.get("declared_kind", "unknown")
        source = "IdentityType tag"
    if native:
        attribution = "verified_ai_binding"
        source = "native resource metadata (not per-session attribution)"
    elif declared == "ai":
        attribution = "declared_ai"
    elif declared in {"human", "workload"}:
        attribution = "declared_" + declared
    elif bindings:
        attribution = "verified_workload_binding"
        source = "workload resource metadata"
    else:
        attribution, source = "unknown", "insufficient evidence"
    return {"account_id": resource.account_id, "arn": resource.resource_arn, "name": resource.resource_id,
            "type": resource.resource_type, "ai_attribution": attribution, "classification_source": source,
            "shared_declared": approval.get("shared", False), "approval_status": approval.get("status", "unknown"),
            "session_actor_attribution": "ambiguous_shared_identity" if approval.get("shared", False) else "AI execution not established by AWS identity alone",
            "evaluation_scope": "NOT_SCANNED" if excluded else "selected",
            "configured_mechanisms": data.get("identity_trust", {}).get("mechanisms", ["iam_user"] if resource.resource_type == "user" else []),
            "observed_mechanisms": sorted({e["mechanism"] for e in data.get("identity_activity", {}).get("events", [])}),
            "evidence": {key: value for key, value in data.items() if key.startswith("identity_") and key != "identity_requested"},
            "missing_facts": [key for key in ("identity_profile", "identity_approval", "identity_policy_context",
                                              *(("identity_trust", "identity_usage") if resource.resource_type == "role" else ())) if key not in data]}


def select_identity_summaries(report, view: str) -> list[dict]:
    """Select evidence-backed review candidates without changing scan coverage."""
    if view == "all":
        return report.identities
    if view == "ai":
        return [item for item in report.identities if item["ai_attribution"] in {"declared_ai", "verified_ai_binding"}]
    if view == "shared":
        return [item for item in report.identities if item["shared_declared"] is True]
    finding_id = {"unowned": "AWSH-IAM-007", "stale": "AWSH-IAM-009"}[view]
    matched = {(finding.account_id, finding.resource_arn) for finding in report.findings if finding.id == finding_id}
    return [item for item in report.identities if (item["account_id"], item["arn"]) in matched]
