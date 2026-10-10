"""Pure evidence-aware comparison; positive edges never prove an absent edge.

Policy 1 compares observations, not remediation or IAM resource incarnations.
The existing rule registry establishes positive predicates. Registered check
evaluators establish negative witnesses only after explicit evidence gates.
"""

from dataclasses import dataclass
import json
import re

from awsherlock.correlation import CorrelationError, resource_ref, resource_ref_to_dict
from awsherlock.evaluation import Report
from awsherlock.identity_validation import agentcore_binding_identity
from awsherlock.leads import CORRELATION_RULES, investigation_leads
from awsherlock.models import Resource
from awsherlock.registry import service_spec
from awsherlock.relationships import normalize_relationships, relationship_to_dict
from awsherlock.snapshot import Snapshot


POLICY_VERSION = 1
STATES = ("NEW", "STILL_OBSERVED", "EVIDENCE_CHANGED", "NO_LONGER_OBSERVED", "UNKNOWN")
BROAD = ("AWSH-IAM-001", "AWSH-IAM-002", "AWSH-IAM-003")
# Each tuple is one required predicate. BROAD is an OR, the others singletons.
LOCAL_PREDICATES = {
    "LAMBDA-URL-BROAD-ROLE": (("AWSH-LAMBDA-001",), ("AWSH-LAMBDA-002",)),
    "PUBLIC-EC2-IMDSV1-BROAD-ROLE": (("AWSH-EC2-004",), ("AWSH-EC2-005",)),
    "UNOWNED-BROAD-IAM-WORKLOAD-ROLE": (("AWSH-IAM-007",), BROAD),
    "STALE-BROAD-IAM-ROLE": (("AWSH-IAM-009",), BROAD),
    "AI-WORKLOAD-BROAD-EXECUTION-ROLE": (),
}


def _resource_key(ref: dict) -> tuple:
    return (ref["account_id"], ref["region"] or "", ref["service"],
            ref["resource_type"], ref["resource_id"])


def _finding_key(ref: dict) -> tuple:
    return (ref.get("check_id", ref.get("id")), ref["service"], ref["account_id"],
            ref["region"] or "", ref["resource_id"])


def _edge_key(edge: dict) -> tuple:
    return (_resource_key(edge["source"]), edge["type"], _resource_key(edge["target"]))


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _evidence(value: object) -> object:
    """All lists in the five current patterns' Finding evidence are sets.

    This is deliberately not a generic snapshot normalizer. Prose, timestamps,
    scan IDs and Finding severity/Lead priority are not security support.
    """
    if isinstance(value, dict):
        return {key: _evidence(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        items = {_canonical(_evidence(item)): _evidence(item) for item in value}
        return [items[key] for key in sorted(items)]
    return value


def _valid_locator(ref: dict) -> bool:
    arn = ref["resource_arn"]
    # AgentCore version identities intentionally have no fabricated ARN.
    if ref["service"] == "agentcore" and ref["resource_type"] == "runtime-version":
        return arn is None and re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]{0,47}-[a-zA-Z0-9]{10}:\d{1,5}",
                                           ref["resource_id"]) is not None
    if not isinstance(arn, str):
        return False
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or re.fullmatch(r"aws(?:-[a-z0-9-]+)?", parts[1]) is None:
        return False
    if parts[2:5] != [ref["service"], ref["region"] or "", ref["account_id"]]:
        return False
    prefixes = {("iam", "role"): "role/", ("lambda", "function"): "function:",
                ("ec2", "instance"): "instance/", ("bedrock", "agent"): "agent/"}
    prefix = prefixes.get((ref["service"], ref["resource_type"]))
    if prefix is None or not parts[5].startswith(prefix):
        return False
    identifier = parts[5][len(prefix):]
    if ref["service"] == "iam":
        if re.fullmatch(r"role/(?:[\x21-\x7e]+/)?[A-Za-z0-9_+=,.@-]{1,64}", parts[5]) is None:
            return False
        identifier = identifier.rsplit("/", 1)[-1]
    return identifier == ref["resource_id"]


def _valid_lambda_urls(resource: Resource) -> bool:
    """Bind every URL configuration to this function, permitting qualifiers."""
    subject = resource.resource_arn.split(":", 5)
    for url in resource.data.get("urls", []):
        arn = url.get("arn")
        parts = arn.split(":", 5) if isinstance(arn, str) else []
        if len(parts) != 6 or parts[:5] != subject[:5]:
            return False
        identity = parts[5].split(":")
        if (len(identity) not in {2, 3} or identity[:2] != ["function", resource.resource_id]
                or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identity[1]) is None):
            return False
        if len(identity) == 3 and re.fullmatch(r"(?:[A-Za-z0-9_-]{1,128}|\$LATEST)", identity[2]) is None:
            return False
    return True


@dataclass
class _Observation:
    snapshot: Snapshot
    report: Report
    leads: dict
    resources: dict
    locators: dict
    edges: dict
    findings: dict


def _observe(snapshot: Snapshot, report: Report) -> _Observation:
    expected = snapshot.metadata
    if any(report.metadata.get(key) != getattr(expected, key)
           for key in ("scan_id", "account_id", "region")):
        raise CorrelationError("Lead delta requires each snapshot's exact report")
    document = investigation_leads(snapshot, report=report)
    resources: dict[tuple, list[Resource]] = {}
    locators: dict[str, set[tuple]] = {}
    for collection in snapshot.services.values():
        for resource in collection.resources:
            key = resource_ref(resource).logical_key
            resources.setdefault(key, []).append(resource)
            if resource.resource_arn is not None:
                locators.setdefault(resource.resource_arn, set()).add(key)
    edges = {_edge_key(data): data for edge in normalize_relationships(snapshot.relationships, snapshot.services)
             for data in (relationship_to_dict(edge),)}
    findings: dict[tuple, list[dict]] = {}
    for finding in report.findings:
        data = finding.to_dict()
        findings.setdefault(_finding_key(data), []).append(data)
    return _Observation(snapshot, report, {lead["lead_id"]: lead for lead in document["leads"]},
                        resources, locators, edges, findings)


def _exact_resource(observation: _Observation, ref: dict) -> tuple[Resource | None, str | None]:
    matches = observation.resources.get(_resource_key(ref), [])
    if not matches:
        return None, "RESOURCE_NOT_OBSERVED"
    if len(matches) != 1:
        return None, "AMBIGUOUS_RESOURCE_IDENTITY"
    resource = matches[0]
    actual = resource_ref_to_dict(resource_ref(resource))
    if len(observation.locators.get(resource.resource_arn, set())) > 1:
        return None, "AMBIGUOUS_RESOURCE_IDENTITY"
    if (ref["resource_arn"] and resource.resource_arn and ref["resource_arn"] != resource.resource_arn):
        return None, "CONFLICTING_RESOURCE_ARN"
    if not _valid_locator(actual):
        return None, "UNVALIDATED_RESOURCE_LOCATOR"
    if resource.service == "lambda" and not _valid_lambda_urls(resource):
        return None, "LAMBDA_URL_IDENTITY_MISMATCH"
    return resource, None


def _check_false(observation: _Observation, ref: dict, identifier: str) -> tuple[bool, list[str]]:
    resource, gap = _exact_resource(observation, ref)
    if gap:
        return False, [gap]
    check = next(check for check in service_spec(resource.service).checks if check.identifier == identifier)
    fact = check.required_fact
    if fact not in resource.data:
        return False, ["REQUIRED_FACT_UNAVAILABLE"]
    # A raw failed read or partial pagination for this resource/service blocks
    # negative claims even if stale/partial facts were retained in the snapshot.
    collection = observation.snapshot.services[resource.service]
    if any(issue.resource_id in {None, resource.resource_id} for issue in collection.issues):
        return False, ["COLLECTION_INCOMPLETE"]
    if resource.service == "iam":
        if identifier in BROAD and resource.data.get("identity_policy_context", {}).get("complete") is not True:
            return False, ["IAM_POLICY_CONTEXT_INCOMPLETE"]
        if identifier not in BROAD:
            if (resource.data.get("identity_requested") is not True
                    or "identity_profile" not in resource.data
                    or resource.data["identity_profile"]["service_linked"]):
                return False, ["GOVERNANCE_EVIDENCE_UNAVAILABLE"]
            if identifier == "AWSH-IAM-007" and ("identity_approval" not in resource.data
                    or resource.data["identity_approval"]["status"] == "unknown"):
                return False, ["OWNER_DECLARATION_INCOMPLETE"]
            if identifier == "AWSH-IAM-009" and resource.data[fact]["status"] != "recorded":
                return False, ["USAGE_TRACKING_UNCERTAIN"]
    # Do not duplicate security rules: validated normalized facts are evaluated
    # by exactly the registered evaluator used by live and offline reporting.
    try:
        results = check.evaluator.evaluate(resource)
    except (ValueError, TypeError, KeyError, AttributeError):
        return False, ["PREDICATE_EVALUATION_UNAVAILABLE"]
    return not results, []


def _ai_role(observation: _Observation, subject: dict) -> tuple[dict | None, list[str]]:
    """A positive edge alone is not exhaustive execution-role inventory."""
    if subject["service"] == "bedrock":
        resource, gap = _exact_resource(observation, subject)
        if gap:
            return None, [gap]
        if any(issue.resource_id in {None, resource.resource_id}
               for issue in observation.snapshot.services["bedrock"].issues):
            return None, ["COLLECTION_INCOMPLETE"]
        role_arn = resource.data.get("execution_role_arn")
        edges = [edge for edge in observation.edges.values()
                 if _resource_key(edge["source"]) == _resource_key(subject) and edge["type"] == "RUNS_AS"]
        if any(edge["target"]["resource_arn"] != role_arn for edge in edges):
            return None, ["EXECUTION_ROLE_BINDING_CONFLICT"]
        candidates = [edge["target"] for edge in edges if edge["target"]["resource_arn"] == role_arn]
    else:
        candidates = []
        for resources in observation.resources.values():
            for role in resources:
                if role.service != "iam" or role.resource_type != "role":
                    continue
                for binding in role.data.get("identity_bindings", []):
                    identity = agentcore_binding_identity(binding)
                    if identity and (identity[2], identity[1], f"{identity[3]}:{identity[5]}") == (
                            subject["account_id"], subject["region"], subject["resource_id"]):
                        if role.resource_arn == binding["role_arn"]:
                            candidates.append(resource_ref_to_dict(resource_ref(role)))
    unique = {_resource_key(candidate): candidate for candidate in candidates}
    if len(unique) > 1:
        return None, ["EXECUTION_ROLE_BINDING_CONFLICT"]
    if not unique:
        return None, ["EXECUTION_ROLE_BINDING_UNAVAILABLE"]
    target = next(iter(unique.values()))
    if target["account_id"] != subject["account_id"] or target["region"] is not None:
        return None, ["ROLE_SCOPE_MISMATCH"]
    edges = [edge for edge in observation.edges.values()
             if _resource_key(edge["source"]) == _resource_key(subject) and edge["type"] == "RUNS_AS"]
    if any(_resource_key(edge["target"]) != _resource_key(target)
           or edge["target"]["resource_arn"] != target["resource_arn"] for edge in edges):
        return None, ["EXECUTION_ROLE_BINDING_CONFLICT"]
    return target, []


def _assessment(observation: _Observation, basis: dict, lead: dict | None) -> dict:
    result = {"scan_id": observation.snapshot.metadata.scan_id,
              "lead_id": lead["lead_id"] if lead else None,
              "assessment": "OBSERVED" if lead else "UNKNOWN",
              "false_predicates": [], "reason_codes": []}
    if lead:
        return result
    rule = next(rule for rule in CORRELATION_RULES if rule.pattern_id == basis["pattern_id"])
    if rule.requires_relationships and not observation.snapshot.supports_relationships:
        result["reason_codes"] = ["RELATIONSHIPS_UNSUPPORTED"]
        return result
    subject = basis["subjects"][0]
    gaps = []
    predicates = [(subject, identifiers) for identifiers in LOCAL_PREDICATES[rule.pattern_id]]
    if rule.pattern_id == "AI-WORKLOAD-BROAD-EXECUTION-ROLE":
        target, role_gaps = _ai_role(observation, subject)
        gaps.extend(role_gaps)
        if target:
            predicates.append((target, BROAD))
    for ref, identifiers in predicates:
        assessments = [_check_false(observation, ref, identifier) for identifier in identifiers]
        if all(is_false for is_false, _ in assessments):
            resource, _ = _exact_resource(observation, ref)
            facts = {check.required_fact for check in service_spec(resource.service).checks
                     if check.identifier in identifiers}
            if resource.service == "iam":
                if identifiers == BROAD:
                    facts.add("identity_policy_context")
                else:
                    facts.update({"identity_profile", "identity_requested"})
                    if identifiers == ("AWSH-IAM-007",):
                        facts.add("identity_approval")
            result["false_predicates"].append({"checks": list(identifiers),
                "resource": resource_ref_to_dict(resource_ref(resource)),
                "facts": {fact: _evidence(resource.data[fact]) for fact in sorted(facts) if fact in resource.data}})
        gaps.extend(gap for _, errors in assessments for gap in errors)
    if result["false_predicates"]:
        result["assessment"] = "NOT_OBSERVED_WITH_EVIDENCE"
        result["reason_codes"] = ["REQUIRED_PREDICATE_FALSE"]
    else:
        # Neither COMPLETE service coverage nor a v2 empty edge array can
        # establish that optional relationship families were collected.
        if rule.requires_relationships:
            gaps.append("RELATIONSHIP_COMPLETENESS_UNAVAILABLE")
        result["reason_codes"] = sorted(set(gaps or ["PREDICATE_NOT_ESTABLISHED"]))
    return result


def _support(observation: _Observation, lead: dict) -> dict:
    gaps = set()
    if lead["pattern_id"] == "AI-WORKLOAD-BROAD-EXECUTION-ROLE":
        _, role_gaps = _ai_role(observation, lead["subjects"][0])
        gaps.update(role_gaps)
    locators = {}
    resources = [*lead["subjects"], *lead["related_resources"]]
    for edge in lead["relationships"]:
        resources.extend((edge["source"], edge["target"]))
    for ref in resources:
        key = _resource_key(ref)
        locators[key] = ref["resource_arn"]
        if ref["account_id"] != observation.snapshot.metadata.account_id:
            gaps.add("RESOURCE_SCOPE_MISMATCH")
        if ref["service"] == "iam" and ref["region"] is not None:
            gaps.add("ROLE_SCOPE_MISMATCH")
        if ref["service"] != "iam" and ref["region"] != observation.snapshot.metadata.region:
            gaps.add("RESOURCE_SCOPE_MISMATCH")
        if not _valid_locator(ref):
            gaps.add("UNVALIDATED_RESOURCE_LOCATOR")
        if ref["service"] != "agentcore":
            resource, gap = _exact_resource(observation, ref)
            if gap:
                gaps.add(gap)
            elif resource.service == "iam" and resource.data.get("identity_policy_context", {}).get("complete") is not True:
                gaps.add("IAM_POLICY_CONTEXT_INCOMPLETE")
    findings = {}
    resource_keys = {_resource_key(ref) for ref in resources}
    for ref in lead["findings"]:
        key = _finding_key(ref)
        identities = observation.locators.get(ref["resource_arn"], set())
        if len(identities) != 1:
            gaps.add("AMBIGUOUS_RESOURCE_IDENTITY" if identities else "SUPPORTING_FINDING_UNAVAILABLE")
            continue
        identity = next(iter(identities))
        if (identity not in resource_keys
                or (identity[0], identity[1], identity[2], identity[4]) != (key[2], key[3], key[1], key[4])):
            gaps.add("SUPPORTING_FINDING_UNAVAILABLE")
            continue
        resource = observation.resources[identity][0]
        _, gap = _exact_resource(observation, resource_ref_to_dict(resource_ref(resource)))
        if gap:
            gaps.add(gap)
            continue
        matches = observation.findings.get(key, [])
        if len(matches) != 1 or matches[0]["resource_arn"] != ref["resource_arn"]:
            gaps.add("SUPPORTING_FINDING_UNAVAILABLE")
        else:
            findings[key] = _evidence(matches[0]["evidence"])
    provenance = {}
    for ref in lead["relationships"]:
        key = _edge_key(ref)
        edge = observation.edges.get(key)
        if edge is None:
            gaps.add("SUPPORTING_RELATIONSHIP_UNAVAILABLE")
        else:
            provenance[key] = _evidence(edge["evidence"])
    services = {ref["service"] for ref in resources if ref["service"] != "agentcore"}
    for service in services:
        rows = [row for row in observation.report.coverage if row["service"] == service]
        if len(rows) != 1 or rows[0]["status"] != "COMPLETE":
            gaps.add("SUPPORT_COVERAGE_INCOMPLETE")
    if not observation.snapshot.supports_relationships:
        gaps.add("RELATIONSHIPS_UNSUPPORTED")
    return {"findings": findings, "edges": provenance, "locators": locators,
            "related": sorted({_resource_key(ref) for ref in lead["related_resources"]}),
            "observed_codes": sorted(statement["code"] for statement in lead["observed"]),
            "gaps": sorted(gaps)}


def _support_comparison(old: dict, new: dict, before: _Observation, after: _Observation,
                        left: dict, right: dict) -> tuple[str, list[dict], str]:
    changes = []
    # Matching complete normalized Finding evidence can establish a security
    # change. Differing support membership cannot: optional edge families have
    # no completeness marker, even with COMPLETE service coverage.
    complete = not old["gaps"] and not new["gaps"]
    for key in sorted(old["findings"].keys() & new["findings"].keys()):
        if complete and old["findings"][key] != new["findings"][key]:
            changes.append({"kind": "FINDING_EVIDENCE_CHANGED", "finding_key": list(key),
                            "before": old["findings"][key], "after": new["findings"][key]})
    if complete:
        if left["pattern_id"] == "AI-WORKLOAD-BROAD-EXECUTION-ROLE":
            old_role, old_gaps = _ai_role(before, left["subjects"][0])
            new_role, new_gaps = _ai_role(after, right["subjects"][0])
            if not old_gaps and not new_gaps and _resource_key(old_role) != _resource_key(new_role):
                changes.append({"kind": "EXECUTION_ROLE_CHANGED", "before": old_role, "after": new_role})
        for key in sorted(old["findings"].keys() ^ new["findings"].keys()):
            lead = right if key in new["findings"] else left
            observation = before if key in new["findings"] else after
            reference = next(ref for ref in lead["findings"] if _finding_key(ref) == key)
            candidates = [ref for ref in [*lead["subjects"], *lead["related_resources"]]
                          if (ref["account_id"], ref["region"] or "", ref["service"], ref["resource_id"])
                          == (key[2], key[3], key[1], key[4])]
            if len(candidates) == 1 and candidates[0]["resource_arn"] == reference["resource_arn"]:
                is_false, _ = _check_false(observation, candidates[0], key[0])
                if is_false:
                    changes.append({"kind": "SUPPORTING_FINDING_ADDED" if key in new["findings"]
                                    else "SUPPORTING_FINDING_NO_LONGER_OBSERVED", "finding_key": list(key),
                                    "before": old["findings"].get(key), "after": new["findings"].get(key)})
    membership_equal = (old["findings"].keys() == new["findings"].keys()
                        and old["edges"].keys() == new["edges"].keys()
                        and old["related"] == new["related"] and old["observed_codes"] == new["observed_codes"])
    provenance_changed = any(old["edges"][key] != new["edges"][key]
                             for key in old["edges"].keys() & new["edges"].keys())
    provenance = "CHANGED" if provenance_changed else "EQUAL" if complete and membership_equal else "UNKNOWN"
    return ("CHANGED" if changes else "EQUAL" if complete and membership_equal else "UNKNOWN", changes, provenance)


def _export_support(lead: dict | None, support: dict | None, observation: _Observation) -> dict | None:
    if lead is None:
        return None
    return {"lead": lead,
            "finding_evidence": [{"finding_key": list(key), "evidence": support["findings"][key]}
                                 for key in sorted(support["findings"])],
            "relationship_evidence": [observation.edges[key] for key in sorted(support["edges"])]}


def _provenance(observation: _Observation) -> dict:
    metadata = observation.snapshot.metadata
    return {"scan_id": metadata.scan_id, "account_id": metadata.account_id, "region": metadata.region,
            "started_at": metadata.started_at.isoformat(), "producer_version": metadata.version,
            "snapshot_schema_version": observation.snapshot.schema_version,
            "supports_relationships": observation.snapshot.supports_relationships}


def compare_lead_delta(before: Snapshot, after: Snapshot, previous: Report, current: Report) -> dict:
    """Evaluate each side independently, then compare explicit logical support."""
    old, new = _observe(before, previous), _observe(after, current)
    same_scope = (before.metadata.account_id, before.metadata.region) == (after.metadata.account_id, after.metadata.region)
    changes = []
    for lead_id in sorted(old.leads.keys() | new.leads.keys()):
        left, right = old.leads.get(lead_id), new.leads.get(lead_id)
        basis = right or left
        before_assessment = _assessment(old, basis, left)
        after_assessment = _assessment(new, basis, right)
        old_support = _support(old, left) if left else None
        new_support = _support(new, right) if right else None
        support_comparison, evidence_changes, provenance_comparison = "UNKNOWN", [], "UNKNOWN"
        reasons = set(before_assessment["reason_codes"] + after_assessment["reason_codes"])
        gaps = {"before": old_support["gaps"] if old_support else before_assessment["reason_codes"],
                "after": new_support["gaps"] if new_support else after_assessment["reason_codes"]}
        reasons.update(code for codes in gaps.values() for code in codes)
        # Reconcile all observed locators, including a non-observed side's
        # matching resources: changed IAM paths cannot become confident deltas.
        locators = {}
        for observation, lead in ((old, left or basis), (new, right or basis)):
            for ref in [*lead["subjects"], *lead["related_resources"]]:
                key = _resource_key(ref)
                candidates = [ref["resource_arn"]] if observation.leads.get(lead_id) else []
                candidates += [item.resource_arn for item in observation.resources.get(key, [])]
                locators.setdefault(key, set()).update(arn for arn in candidates if arn is not None)
        conflicts = any(len(arns) > 1 for arns in locators.values())
        invalid = any(code in {"RESOURCE_SCOPE_MISMATCH", "ROLE_SCOPE_MISMATCH", "UNVALIDATED_RESOURCE_LOCATOR",
                              "AMBIGUOUS_RESOURCE_IDENTITY", "CONFLICTING_RESOURCE_ARN", "EXECUTION_ROLE_BINDING_CONFLICT",
                              "LAMBDA_URL_IDENTITY_MISMATCH"}
                      for codes in gaps.values() for code in codes)
        if not same_scope or conflicts or invalid:
            state = "UNKNOWN"
            reasons.add("SCOPE_MISMATCH" if not same_scope else "CONFLICTING_RESOURCE_ARN" if conflicts else "IDENTITY_UNCERTAIN")
        elif left and right:
            support_comparison, evidence_changes, provenance_comparison = _support_comparison(
                old_support, new_support, old, new, left, right)
            state = "EVIDENCE_CHANGED" if support_comparison == "CHANGED" else "STILL_OBSERVED"
            reasons.add("SECURITY_SUPPORT_CHANGED" if evidence_changes else "POSITIVE_OBSERVATIONS_ON_BOTH_SIDES")
            if support_comparison == "UNKNOWN" and not any(gaps.values()):
                reasons.add("SUPPORT_MEMBERSHIP_INCOMPARABLE")
        elif right and before_assessment["assessment"] == "NOT_OBSERVED_WITH_EVIDENCE":
            state = "NEW"
        elif left and after_assessment["assessment"] == "NOT_OBSERVED_WITH_EVIDENCE":
            state = "NO_LONGER_OBSERVED"
        else:
            state = "UNKNOWN"
        if provenance_comparison == "CHANGED":
            reasons.add("RELATIONSHIP_PROVENANCE_CHANGED")
        changes.append({"lead_id": lead_id, "pattern_id": basis["pattern_id"], "priority": basis["priority"],
                        "subjects": basis["subjects"], "state": state,
                        "before": before_assessment, "after": after_assessment,
                        "support_comparison": support_comparison, "provenance_comparison": provenance_comparison,
                        "evidence_changes": evidence_changes, "reason_codes": sorted(reasons), "evidence_gaps": gaps,
                        "support": {"before": _export_support(left, old_support, old),
                                    "after": _export_support(right, new_support, new)}})
    return {"schema_version": 1, "comparison_policy_version": POLICY_VERSION,
            "before": _provenance(old), "after": _provenance(new),
            "summary": {state: sum(row["state"] == state for row in changes) for state in STATES},
            "observed_counts": {"before": len(old.leads), "after": len(new.leads)}, "changes": changes}
