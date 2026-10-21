"""Evidence semantics over the existing five public synthetic Lead scenarios."""

from copy import deepcopy
from dataclasses import replace
import importlib
import json

import pytest

from awsherlock.collectors.common import CollectionIssue, CollectionResult
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.leads import investigation_leads
from test_lead_delta import pair, agentcore_snapshot, LAMBDA, EC2, OWNER, STALE, AI


def engine():
    return importlib.import_module("awsherlock.investigation_engine")


def selected(value, pattern):
    result = engine().build_investigations(value).to_dict()
    return next(row for row in result["investigations"] if row["pattern_id"] == pattern)


@pytest.mark.parametrize(
    "pattern,score,priority",
    [
        (LAMBDA, 5, "HIGH"),
        (EC2, 6, "HIGH"),
        (OWNER, 4, "MEDIUM"),
        (STALE, 3, "MEDIUM"),
        (AI, 3, "MEDIUM"),
    ],
)
def test_existing_patterns_become_traceable_context_without_changing_leads(
    pattern, score, priority
):
    value = pair(pattern)
    original = deepcopy(investigation_leads(value))
    row = selected(value, pattern)
    lead = next(item for item in original["leads"] if item["pattern_id"] == pattern)
    assert row["lead_id"] == lead["lead_id"]
    assert row["id"] == "investigation:" + lead["lead_id"]
    assert row["priority"] == priority and row["priority_score"] == score
    assert row["priority_status"] == "PROVISIONAL"
    assert row["observed"] and row["inferred"] and row["unknown"]
    assert row["recommended_actions"]
    assert [r["reference"] for r in row["supporting_findings"]] == lead["findings"]
    assert [r["reference"] for r in row["supporting_relationships"]] == lead["relationships"]
    refs = {r["id"] for r in row["supporting_findings"] + row["supporting_relationships"]}
    refs.update(gap["id"] for gap in row["coverage_gaps"])
    for condition in row["observed"] + row["inferred"]:
        assert condition["evidence"] and {ref["id"] for ref in condition["evidence"]} <= refs
    assert sum(f["points"] for f in row["priority_factors"]) == score
    assert all(f["explanation"] and f["evidence"] for f in row["priority_factors"])
    assert investigation_leads(value) == original


def test_permutations_and_source_time_do_not_change_investigation_bytes():
    value = pair(EC2)
    saved = deepcopy(value.to_dict())
    first = engine().render_investigations_json(engine().build_investigations(value))
    assert value.to_dict() == saved
    value.services = dict(reversed(list(value.services.items())))
    for collection in value.services.values():
        collection.resources.reverse()
        collection.issues.reverse()
    value.relationships = tuple(reversed(value.relationships))
    value.metadata = replace(value.metadata, scan_id="different-scan", version="historical")
    assert engine().render_investigations_json(engine().build_investigations(value)) == first
    document = json.loads(first)
    assert document["schema_version"] == 1 and document["priority_policy_version"] == 1
    assert document["kind"] == "contextual-investigations"


@pytest.mark.parametrize(
    "message,reason",
    [
        ("AccessDenied", "ACCESS_DENIED"),
        ("AWS request throttled", "THROTTLED"),
        ("AWS request failed", "COLLECTION_OR_EVALUATION_INCOMPLETE"),
    ],
)
def test_failed_reads_keep_positive_indicators_but_expose_gaps(message, reason):
    value = pair(EC2)
    value.services["iam"].issues.append(CollectionIssue("worker", "GetRolePolicy", message))
    row = selected(value, EC2)
    assert row["priority_status"] == "PROVISIONAL" and row["priority_score"] == 6
    assert any(gap["reason_code"] == reason for gap in row["coverage_gaps"])
    assert any(gap["code"] == "SUPPORT_COVERAGE_INCOMPLETE" for gap in row["coverage_gaps"])
    assert row["observed"]


def test_public_address_never_proves_reachability_or_credential_access():
    row = selected(pair(EC2), EC2)
    assert "NETWORK_REACHABILITY_NOT_EVALUATED" in {item["code"] for item in row["unknown"]}
    assert "CREDENTIAL_ACCESS_NOT_PROVEN" in {item["code"] for item in row["unknown"]}
    assert all(item["assumptions"] for item in row["inferred"])
    assert "effective" in row["priority_explanation"].lower()


@pytest.mark.parametrize("pattern", [LAMBDA, STALE])
def test_historical_v1_stays_explicitly_limited(pattern):
    row = selected(pair(pattern, version=1), pattern)
    assert row["supporting_relationships"] == []
    assert "RELATIONSHIPS_UNSUPPORTED" in {gap["code"] for gap in row["coverage_gaps"]}
    assert row["priority_status"] == "PROVISIONAL"


def test_agentcore_version_reference_is_retained_without_invented_arn():
    row = selected(agentcore_snapshot("7"), AI)
    subject = next(ref for ref in row["resources"] if ref["service"] == "agentcore")
    assert subject["resource_type"] == "runtime-version"
    assert subject["resource_id"].endswith(":7")
    assert subject["resource_arn"] is None


def test_identity_conflict_moves_claims_to_unknown_and_blocks_priority():
    value = pair(LAMBDA)
    value.services["lambda"].resources[0].data["urls"][0]["arn"] += "-other"
    row = selected(value, LAMBDA)
    assert row["priority"] == "UNASSESSED" and row["priority_score"] is None
    assert row["priority_status"] == "BLOCKED"
    assert row["observed"] == [] and row["inferred"] == []
    assert "LAMBDA_URL_IDENTITY_MISMATCH" in {gap["code"] for gap in row["coverage_gaps"]}


def test_no_leads_with_partial_inventory_is_unknown_not_safe():
    value = pair(EC2)
    value.services["ec2"] = CollectionResult(
        [], [CollectionIssue(None, "DescribeInstances", "AccessDenied")]
    )
    result = engine().build_investigations(value).to_dict()
    assert not result["investigations"] and result["incomplete"]
    assert result["coverage_gaps"]
    assert "safety" in result["limitations"].lower()


def test_foreign_report_is_rejected_and_selected_checks_are_respected():
    value = pair(LAMBDA)
    report = evaluate_snapshot(value)
    report.metadata["account_id"] = "999999999999"
    with pytest.raises(ValueError, match="scope"):
        engine().build_investigations(value, report=report)
    report = evaluate_snapshot(value, selected_checks=["AWSH-LAMBDA-001"])
    assert not engine().build_investigations(value, report=report).investigations


def test_arbitrary_payloads_and_issue_messages_are_not_copied():
    value = pair(EC2)
    value.services["iam"].issues.append(
        CollectionIssue("worker", "SecretMarker123", "AccessDenied SECRET_SENTINEL")
    )
    value.services["iam"].resources[0].data["identity_profile"]["boundary"] = "SECRET_SENTINEL"
    rendered = engine().render_investigations_json(engine().build_investigations(value))
    assert "SECRET_SENTINEL" not in rendered and "SecretMarker123" not in rendered
    assert '"evidence": {' not in rendered


def test_evidence_reference_kinds_prevent_identity_collisions_and_detach_serialization():
    models = importlib.import_module("awsherlock.investigation_models")
    from awsherlock.correlation import finding_ref

    value = pair(LAMBDA)
    finding = evaluate_snapshot(value).findings[0]
    ref = models.EvidenceRef.from_reference(finding_ref(finding))
    assert ref.kind == "FINDING" and ref.id.startswith("finding:")
    with pytest.raises(ValueError):
        models.EvidenceRef(kind="invented", id="x")
    result = engine().build_investigations(value)
    exported = result.to_dict()
    exported["investigations"][0]["observed"].clear()
    assert result.to_dict()["investigations"][0]["observed"]


def test_multiple_overlapping_broad_checks_contribute_one_factor():
    value = pair(EC2)
    value.services["iam"].resources[0].data["statements"] = [
        {
            "effect": "Allow",
            "conditional": False,
            "actions": ["*"],
            "resources": ["*"],
            "not_actions": False,
            "not_resources": False,
        }
    ]
    row = selected(value, EC2)
    assert row["priority_score"] == 6
    assert (
        len(
            [
                factor
                for factor in row["priority_factors"]
                if factor["code"] == "BROAD_PERMISSION_INDICATOR"
            ]
        )
        == 1
    )
    assert len(row["supporting_findings"]) == 5


def test_boundary_and_deny_context_never_claim_effective_administration():
    value = pair(EC2)
    value.services["iam"].resources[0].data["identity_profile"][
        "boundary"
    ] = "arn:aws:iam::123456789012:policy/RestrictiveBoundary"
    value.services["iam"].resources[0].data["statements"] = [
        {
            "effect": "Deny",
            "conditional": False,
            "actions": ["*"],
            "resources": ["*"],
            "not_actions": False,
            "not_resources": False,
        }
    ]
    row = selected(value, EC2)
    assert row["priority_score"] == 6 and row["priority_status"] == "PROVISIONAL"
    assert "EFFECTIVE_IAM_PERMISSIONS_NOT_EVALUATED" in {c["code"] for c in row["unknown"]}
    assert not any("administrator" in c["text"].lower() for c in row["inferred"])


def test_unknown_provenance_is_minimized_and_marks_export_incomplete():
    from awsherlock.models import RelationshipEvidence

    value = pair(EC2)
    edge = value.relationships[0]
    value.relationships = (
        replace(
            edge,
            evidence=(
                RelationshipEvidence(
                    service="iam", fact="identity_bindings", operation="GetSecretMarker123"
                ),
            ),
        ),
    )
    result = engine().build_investigations(value)
    assert result.incomplete
    assert "GetSecretMarker123" not in engine().render_investigations_json(result)
    assert "PROVENANCE_FIELD_UNAVAILABLE" in {
        gap.code for row in result.investigations for gap in row.coverage_gaps
    }


def test_absent_support_never_introduces_resolved_delta():
    from awsherlock.diff import compare_snapshots

    before, after = pair(EC2), pair(EC2)
    after.relationships = ()
    assert not any(
        row.pattern_id == EC2 for row in engine().build_investigations(after).investigations
    )
    changes = compare_snapshots(before, after, include_leads=True)["lead_delta"]["changes"]
    assert next(row for row in changes if row["pattern_id"] == EC2)["state"] == "UNKNOWN"


def test_reuses_one_evaluation_and_correlation_for_many_leads(monkeypatch):
    from test_leads_v2 import function, runs_as

    value = pair(LAMBDA)
    for index in range(15):
        workload = function(f"fn{index}")
        value.services["lambda"].resources.append(workload)
        value.relationships += (runs_as(workload, value.services["iam"].resources[0]),)
    module = engine()
    evaluate, correlate = module.evaluate_snapshot, module.investigation_leads
    counts = {"evaluate": 0, "correlate": 0}

    def evaluation(value):
        counts["evaluate"] += 1
        return evaluate(value)

    def correlation(value, **kwargs):
        counts["correlate"] += 1
        return correlate(value, **kwargs)

    monkeypatch.setattr(module, "evaluate_snapshot", evaluation)
    monkeypatch.setattr(module, "investigation_leads", correlation)
    result = module.build_investigations(value)
    assert len([row for row in result.investigations if row.pattern_id == LAMBDA]) == 16
    assert counts == {"evaluate": 1, "correlate": 1}


@pytest.mark.parametrize(
    "name,incomplete", [("contextual-ec2-v2.json", False), ("contextual-ec2-partial-v2.json", True)]
)
def test_saved_historical_synthetic_fixtures_remain_replayable(name, incomplete):
    from pathlib import Path
    from awsherlock.snapshot import read_snapshot

    value = read_snapshot(Path(__file__).parent / "fixtures" / name)
    result = engine().build_investigations(value)
    assert result.incomplete is incomplete
    assert len(result.investigations) == 1
    assert result.investigations[0].priority_score == 6


def test_cross_process_hash_randomization_preserves_json_bytes():
    from pathlib import Path
    import os
    import subprocess
    import sys

    fixture = Path(__file__).parent / "fixtures" / "contextual-ec2-v2.json"
    outputs = []
    for seed in ("1", "41", "203"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        process = subprocess.run(
            [sys.executable, "-m", "awsherlock", "investigate", str(fixture), "--contextual"],
            env=env,
            capture_output=True,
            check=True,
        )
        outputs.append(process.stdout)
    assert outputs[0] == outputs[1] == outputs[2]


def test_suppression_annotations_do_not_remove_investigation_support():
    value = pair(EC2)
    report = evaluate_snapshot(value)
    before = engine().render_investigations_json(
        engine().build_investigations(value, report=report)
    )
    report.suppression_matches = {
        index: {"reason": "owner-approved exception"} for index in range(len(report.findings))
    }
    assert (
        engine().render_investigations_json(engine().build_investigations(value, report=report))
        == before
    )


@pytest.mark.parametrize(
    "identity",
    [
        "finding:",
        "finding:garbage",
        "finding:" + "a" * 63,
        "finding:" + "A" * 64,
        "relationship:" + "a" * 64,
    ],
)
def test_evidence_references_reject_invalid_or_wrong_kind_digests(identity):
    from awsherlock.investigation_models import EvidenceRef

    with pytest.raises(ValueError):
        EvidenceRef(kind="FINDING", id=identity)


def test_scope_coverage_recognizes_all_registered_service_operations():
    value = pair(EC2)
    value.services["s3"] = CollectionResult(
        [], [CollectionIssue(None, "ListBuckets", "AccessDenied")]
    )
    value.services["kms"] = CollectionResult(
        [], [CollectionIssue(None, "ListKeys", "AWS request timed out")]
    )
    result = engine().build_investigations(value)
    gates = [gap.to_dict() for gap in result.coverage_gaps]
    assert any(
        gap["operation"] == "ListBuckets"
        and gap["reason_code"] == "ACCESS_DENIED"
        and gap["region"] is None
        for gap in gates
    )
    assert any(
        gap["operation"] == "ListKeys" and gap["reason_code"] == "REQUEST_TIMEOUT" for gap in gates
    )
    assert not any(gap["code"] == "PROVENANCE_FIELD_UNAVAILABLE" for gap in gates)
    assert not selected(value, EC2)["coverage_gaps"]  # unrelated failures stay scope-wide
