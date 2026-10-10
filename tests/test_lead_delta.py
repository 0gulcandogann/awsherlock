"""Conservative offline Lead transitions over public synthetic fixtures."""

from dataclasses import replace
import json
import hashlib
import os
import subprocess
import sys

import pytest

from awsherlock.collectors.common import CollectionIssue, CollectionResult
from awsherlock.diff import compare_snapshots, render_diff_json
from awsherlock.correlation import CorrelationError
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.lead_delta import compare_lead_delta
from awsherlock.models import Relationship, RelationshipEvidence, RelationshipType, ResourceRef
from test_leads_v2 import ACCOUNT, REGION, function, instance, role, runs_as, snapshot


LAMBDA = "LAMBDA-URL-BROAD-ROLE"
EC2 = "PUBLIC-EC2-IMDSV1-BROAD-ROLE"
OWNER = "UNOWNED-BROAD-IAM-WORKLOAD-ROLE"
STALE = "STALE-BROAD-IAM-ROLE"
AI = "AI-WORKLOAD-BROAD-EXECUTION-ROLE"


def render_snapshot_json(value):
    return json.dumps(value.to_dict(), sort_keys=True)


def pair(pattern, *, risky=True, version=2):
    execution_role = role(unowned=pattern == OWNER and risky, stale=pattern == STALE and risky)
    workload = instance(imdsv1=risky) if pattern == EC2 else function(risky=risky if pattern == LAMBDA else True)
    if pattern == AI:
        workload = replace(workload, service="bedrock", resource_type="agent", resource_id="ABCDEFGHIJ",
                           resource_arn=f"arn:aws:bedrock:{workload.region}:{workload.account_id}:agent/ABCDEFGHIJ",
                           data={"agent_version": "DRAFT", "guardrail_configuration": {"identifier": None, "version": None},
                                 "execution_role_arn": execution_role.resource_arn})
        if not risky:
            execution_role = replace(execution_role, data={**execution_role.data, "attached": []})
    result = snapshot([workload, execution_role], relationships=(runs_as(workload, execution_role),)
                      if version == 2 else (), version=version)
    if pattern == AI:
        result.services["bedrock"].completed_operations = ["ListAgents"]
    return result


def rows(before, after, pattern=LAMBDA):
    document = compare_snapshots(before, after, include_leads=True)
    assert document["schema_version"] == 2
    return [row for row in document["lead_delta"]["changes"] if row["pattern_id"] == pattern]


@pytest.mark.parametrize("pattern", [LAMBDA, EC2, OWNER, STALE, AI])
def test_equal_support_independent_scan_ids(pattern):
    before, after = pair(pattern), pair(pattern)
    after = replace(after, metadata=replace(after.metadata, scan_id="after-independent"))
    row = rows(before, after, pattern)[0]
    assert row["state"] == "STILL_OBSERVED"
    assert row["support_comparison"] == "EQUAL"
    assert row["before"]["scan_id"] != row["after"]["scan_id"]
    assert row["before"]["lead_id"] == row["after"]["lead_id"]


@pytest.mark.parametrize("pattern", [LAMBDA, EC2, OWNER, STALE, AI])
@pytest.mark.parametrize("direction", ["new", "gone"])
def test_transitions_require_false_witness(pattern, direction):
    safe, risky = pair(pattern, risky=False), pair(pattern)
    before, after = (safe, risky) if direction == "new" else (risky, safe)
    row = rows(before, after, pattern)[0]
    assert row["state"] == ("NEW" if direction == "new" else "NO_LONGER_OBSERVED")
    false_side = row["before"] if direction == "new" else row["after"]
    assert false_side["assessment"] == "NOT_OBSERVED_WITH_EVIDENCE"
    assert false_side["false_predicates"]
    assert false_side["false_predicates"][0]["facts"]


def test_missing_resource_is_unknown_not_resolution():
    after = snapshot([], version=2)
    after.services["lambda"] = CollectionResult()
    row = rows(pair(LAMBDA), after)[0]
    assert row["state"] == "UNKNOWN"
    assert "RESOURCE_NOT_OBSERVED" in row["after"]["reason_codes"]


@pytest.mark.parametrize("pattern", [EC2, OWNER, AI])
def test_missing_relationship_is_unknown(pattern):
    after = replace(pair(pattern), relationships=())
    assert rows(pair(pattern), after, pattern)[0]["state"] == "UNKNOWN"


def test_independent_ec2_false_witness_does_not_need_edges():
    after = replace(pair(EC2, risky=False), relationships=())
    assert rows(pair(EC2), after, EC2)[0]["state"] == "NO_LONGER_OBSERVED"


def test_access_denied_prevents_false_witness():
    after = pair(LAMBDA, risky=False)
    after.services["lambda"].issues.append(CollectionIssue("fn", "ListFunctionUrlConfigs", "AccessDenied"))
    assert rows(pair(LAMBDA), after)[0]["state"] == "UNKNOWN"


def test_default_diff_document_unchanged():
    before, after = pair(LAMBDA, risky=False), pair(LAMBDA)
    default = compare_snapshots(before, after)
    opt_in = compare_snapshots(before, after, include_leads=True)
    opt_in.pop("lead_delta")
    opt_in["schema_version"] = 1
    assert render_diff_json(default) == render_diff_json(opt_in)
    assert json.loads(render_diff_json(default))["schema_version"] == 1
    # Frozen from HEAD 3986f82's original diff implementation before M1.
    assert hashlib.sha256(render_diff_json(default).encode()).hexdigest() == (
        "d39439ad124b3f59eeeb109605fb6d0b625317a9aaeeac47f4b72a9ff7af0c3b")


@pytest.mark.parametrize("pattern", [LAMBDA, EC2, OWNER, STALE, AI])
def test_changed_matching_finding_evidence(pattern):
    after = pair(pattern)
    if pattern == LAMBDA:
        resource = after.services["lambda"].resources[0]
        resource.data["role_policies"].append("arn:aws:iam::aws:policy/PowerUserAccess")
    elif pattern == EC2:
        after.services["ec2"].resources[0].data["addresses"].append("198.51.100.11")
    elif pattern == STALE:
        after.services["iam"].resources[0].data["identity_usage"]["last_used_days"] = 130
    elif pattern == OWNER:
        after.services["iam"].resources[0].data["identity_profile"]["boundary"] = f"arn:aws:iam::{ACCOUNT}:policy/Boundary"
    else:
        execution_role = after.services["iam"].resources[0]
        execution_role.data["statements"] = role(broad_check="AWSH-IAM-002").data["statements"]
        # Compare the same positive wildcard Finding, not an added row alone.
        before = pair(pattern)
        before.services["iam"].resources[0].data["statements"] = role(broad_check="AWSH-IAM-002").data["statements"]
        execution_role.data["statements"][0]["actions"] = ["s3:*", "ec2:*"]
        row = rows(before, after, pattern)[0]
        assert row["state"] == "EVIDENCE_CHANGED"
        assert row["support_comparison"] == "CHANGED"
        return
    row = rows(pair(pattern), after, pattern)[0]
    assert row["state"] == "EVIDENCE_CHANGED"
    assert row["support_comparison"] == "CHANGED"
    assert row["evidence_changes"][0]["kind"] == "FINDING_EVIDENCE_CHANGED"


@pytest.mark.parametrize("pattern", [LAMBDA, EC2, OWNER, STALE, AI])
def test_provenance_only_does_not_claim_security_change(pattern):
    after = pair(pattern)
    edge = after.relationships[0]
    after = replace(after, relationships=(replace(edge, evidence=(RelationshipEvidence(
        service="iam", fact="identity_bindings", operation="GetRole"),)),))
    row = rows(pair(pattern), after, pattern)[0]
    # STALE does not consume relationships, so they are deliberately excluded.
    assert row["state"] == "STILL_OBSERVED"
    assert row["support_comparison"] == "EQUAL"
    assert row["provenance_comparison"] == ("EQUAL" if pattern == STALE else "CHANGED")
    assert not row["evidence_changes"]
    if pattern != STALE:
        assert row["support"]["after"]["relationship_evidence"][0]["evidence"][0]["operation"] == "GetRole"


@pytest.mark.parametrize("pattern", [OWNER, STALE, AI])
def test_incomplete_iam_policy_reads_prevent_false_broad_predicate(pattern):
    before = pair(pattern)
    after = pair(pattern)
    execution_role = after.services["iam"].resources[0]
    execution_role.data["attached"] = []
    execution_role.data["identity_policy_context"]["complete"] = False
    row = rows(before, after, pattern)[0]
    assert row["state"] == "UNKNOWN"
    assert "IAM_POLICY_CONTEXT_INCOMPLETE" in row["after"]["reason_codes"]


@pytest.mark.parametrize("pattern", [LAMBDA, EC2, OWNER, STALE, AI])
def test_both_observed_with_incomplete_support_never_equal(pattern):
    after = pair(pattern)
    after.services["iam"].issues.append(CollectionIssue("worker", "GetRolePolicy", "AccessDenied"))
    row = rows(pair(pattern), after, pattern)[0]
    assert row["state"] == "STILL_OBSERVED"
    assert row["support_comparison"] == "UNKNOWN"


def test_optional_edge_disappearance_is_not_security_change():
    after = replace(pair(LAMBDA), relationships=())
    row = rows(pair(LAMBDA), after)[0]
    assert row["state"] == "STILL_OBSERVED"
    assert row["support_comparison"] == "UNKNOWN"


@pytest.mark.parametrize("pattern", [EC2, OWNER, AI])
def test_unsupported_v1_relationships_prevent_transition(pattern):
    row = rows(pair(pattern), pair(pattern, risky=False, version=1), pattern)[0]
    assert row["state"] == "UNKNOWN"
    assert "RELATIONSHIPS_UNSUPPORTED" in row["after"]["reason_codes"]


@pytest.mark.parametrize("pattern", [LAMBDA, STALE])
def test_v1_finding_only_leads_remain_observable(pattern):
    row = rows(pair(pattern, version=1), pair(pattern, version=1), pattern)[0]
    assert row["state"] == "STILL_OBSERVED"
    assert row["support_comparison"] == "UNKNOWN"
    assert rows(pair(pattern, version=1), pair(pattern, risky=False, version=1), pattern)[0]["state"] == "NO_LONGER_OBSERVED"


@pytest.mark.parametrize("pattern", [LAMBDA, EC2, OWNER, STALE, AI])
def test_same_names_different_accounts_never_match(pattern):
    after = pair(pattern)
    other_account = "999999999999"
    # Rebuild through snapshot JSON to change every reference consistently.
    from awsherlock.snapshot import snapshot_from_dict
    data = json.loads(render_snapshot_json(after).replace(ACCOUNT, other_account))
    after = snapshot_from_dict(data)
    compared = rows(pair(pattern), after, pattern)
    assert len(compared) == 2
    assert all(row["state"] == "UNKNOWN" for row in compared)
    assert len({row["lead_id"] for row in compared}) == 2


def test_regional_scope_isolation_and_iam_global_subject():
    from awsherlock.snapshot import snapshot_from_dict
    after = snapshot_from_dict(json.loads(render_snapshot_json(pair(LAMBDA)).replace(REGION, "us-east-1")))
    assert len(rows(pair(LAMBDA), after)) == 2
    assert all(row["state"] == "UNKNOWN" for row in rows(pair(LAMBDA), after))
    after = snapshot_from_dict(json.loads(render_snapshot_json(pair(STALE)).replace(REGION, "us-east-1")))
    row = rows(pair(STALE), after, STALE)[0]
    assert row["subjects"][0]["region"] is None
    assert row["before"]["lead_id"] == row["after"]["lead_id"]
    assert row["state"] == "UNKNOWN"  # Preserve whole-snapshot diff scope contract.


@pytest.mark.parametrize("pattern", [EC2, OWNER, STALE, AI])
def test_conflicting_nonnull_role_paths_block_matching(pattern):
    from awsherlock.snapshot import snapshot_from_dict
    before = pair(pattern)
    text = render_snapshot_json(pair(pattern))
    after = snapshot_from_dict(json.loads(text.replace(f":role/worker", ":role/changed-path/worker")))
    row = rows(before, after, pattern)[0]
    assert row["state"] == "UNKNOWN"
    assert "CONFLICTING_RESOURCE_ARN" in row["reason_codes"]


def agentcore_snapshot(version="1", *, broad=True):
    from awsherlock.relationships import project_relationships
    execution_role = role(broad_check="AWSH-IAM-001" if broad else "none")
    execution_role.data["identity_bindings"] = [{"service": "agentcore", "region": REGION,
        "resource_arn": f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/example-0123456789",
        "resource_version": version, "role_arn": execution_role.resource_arn}]
    value = snapshot([execution_role], version=2)
    value.relationships = project_relationships(value.services)
    return value


def test_agentcore_versions_have_distinct_ids_and_missing_version_is_unknown():
    before, after = agentcore_snapshot("1"), agentcore_snapshot("2")
    compared = rows(before, after, AI)
    assert len(compared) == 2
    assert len({row["lead_id"] for row in compared}) == 2
    assert all(row["state"] == "UNKNOWN" for row in compared)
    assert all(row["subjects"][0]["resource_arn"] is None for row in compared)


def test_exact_agentcore_binding_allows_validated_false_role_signal():
    row = rows(agentcore_snapshot(), agentcore_snapshot(broad=False), AI)[0]
    assert row["state"] == "NO_LONGER_OBSERVED"


def test_inputs_never_mix_findings_and_relationships():
    before = pair(EC2)
    before.relationships = ()
    after = pair(EC2)
    after.services["iam"].resources[0].data["attached"] = []
    assert rows(before, after, EC2) == []


def test_exact_report_pairing_for_delta():
    before, after = pair(LAMBDA), pair(LAMBDA)
    after.metadata = replace(after.metadata, scan_id="other")
    with pytest.raises(CorrelationError, match="exact report"):
        compare_lead_delta(before, after, evaluate_snapshot(after), evaluate_snapshot(before))


def test_evidence_order_and_unrelated_runtime_dates_are_not_security_changes():
    before, after = pair(LAMBDA), pair(LAMBDA)
    for value in (before, after):
        value.services["lambda"].resources[0].data["role_policies"].append("arn:aws:iam::aws:policy/PowerUserAccess")
    after.services["lambda"].resources[0].data["role_policies"].reverse()
    after.services["lambda"].resources[0].data["runtime"]["evaluated_on"] = "2026-10-09"
    row = rows(before, after)[0]
    assert row["state"] == "STILL_OBSERVED"
    assert row["support_comparison"] == "EQUAL"


@pytest.mark.parametrize("fault", ["AccessDenied", "Throttling", "Partial pagination"])
def test_incomplete_collection_blocks_new_and_disappearing(fault):
    safe, risky = pair(LAMBDA, risky=False), pair(LAMBDA)
    safe.services["lambda"].issues.append(CollectionIssue(None, "ListFunctions", fault))
    assert rows(safe, risky)[0]["state"] == "UNKNOWN"
    assert rows(risky, safe)[0]["state"] == "UNKNOWN"


def test_stale_tracking_unknown_and_missing_owner_declarations_are_unknown():
    after = pair(STALE)
    after.services["iam"].resources[0].data["identity_usage"] = {
        "status": "unknown", "last_used_days": None, "created_days": 200}
    assert rows(pair(STALE), after, STALE)[0]["state"] == "UNKNOWN"
    after = pair(OWNER, risky=False)
    after.services["iam"].resources[0].data.pop("identity_approval")
    assert rows(pair(OWNER), after, OWNER)[0]["state"] == "UNKNOWN"


def test_identical_normalized_inputs_have_identical_bytes():
    first = render_diff_json(compare_snapshots(pair(EC2), pair(EC2), include_leads=True))
    second = render_diff_json(compare_snapshots(pair(EC2), pair(EC2), include_leads=True))
    assert first.encode() == second.encode()


def test_hash_seed_subprocess_outputs_match():
    script = """import sys; sys.path.insert(0, 'tests')
from test_lead_delta import *
before = pair(OWNER)
after = pair(OWNER)
after.services['iam'].resources[0].data['identity_profile']['boundary'] = 'changed'
print(render_diff_json(compare_snapshots(before, after, include_leads=True)), end='')
"""
    results = [subprocess.run([sys.executable, "-c", script], env={**os.environ, "PYTHONHASHSEED": seed},
                             capture_output=True, check=True).stdout for seed in ("1", "777")]
    assert results[0] == results[1]


def test_cli_offline_and_finding_thresholds_unchanged(tmp_path, monkeypatch):
    import boto3
    import botocore.session
    from typer.testing import CliRunner
    from awsherlock.cli import app
    from awsherlock.aws.context import ScanContext
    import awsherlock.cli as cli

    def forbidden(*args, **kwargs):
        pytest.fail("Offline diff created an AWS session/client")

    monkeypatch.setattr(boto3, "Session", forbidden)
    monkeypatch.setattr(boto3.session, "Session", forbidden)
    monkeypatch.setattr(botocore.session, "get_session", forbidden)
    monkeypatch.setattr(boto3, "client", forbidden)
    monkeypatch.setattr(ScanContext, "client", forbidden)
    monkeypatch.setattr(cli, "create_scan_context", forbidden)
    before, after = pair(LAMBDA, risky=False), pair(LAMBDA)
    paths = [tmp_path / "before.json", tmp_path / "after.json"]
    for path, value in zip(paths, (before, after)):
        path.write_text(render_snapshot_json(value), encoding="utf-8")
    runner = CliRunner()
    common = ["diff", *(str(path) for path in paths), "--output", "json", "--fail-on", "new"]
    original_bytes = [path.read_bytes() for path in paths]
    default = runner.invoke(app, common)
    opt_in = runner.invoke(app, [*common, "--include-leads"])
    assert default.exit_code == opt_in.exit_code == 3
    assert json.loads(default.stdout)["schema_version"] == 1
    assert json.loads(opt_in.stdout)["schema_version"] == 2
    assert "lead_delta" not in json.loads(default.stdout)
    assert [path.read_bytes() for path in paths] == original_bytes
    before = pair(LAMBDA)
    before.relationships = ()
    paths[0].write_text(render_snapshot_json(before), encoding="utf-8")
    # Unknown optional support alone does not create a new exit threshold.
    assert runner.invoke(app, common).exit_code == runner.invoke(app, [*common, "--include-leads"]).exit_code == 0
    assert all(path.is_file() for path in paths)

    for path, value in zip(paths, (pair(EC2), replace(pair(EC2), relationships=()))):
        path.write_text(render_snapshot_json(value), encoding="utf-8")
    plain = runner.invoke(app, common)
    enriched = runner.invoke(app, [*common, "--include-leads"])
    assert plain.exit_code == enriched.exit_code == 0
    assert json.loads(enriched.stdout)["lead_delta"]["summary"]["UNKNOWN"] == 1


def test_real_cli_subprocess_accepts_opt_in(tmp_path):
    # CI runs this with an installed wheel; local source runs use PYTHONPATH.
    paths = [tmp_path / "before.json", tmp_path / "after.json"]
    for path in paths:
        path.write_text(render_snapshot_json(pair(LAMBDA)), encoding="utf-8")
    result = subprocess.run([sys.executable, "-m", "awsherlock", "diff", *(str(path) for path in paths),
                             "--include-leads", "--output", "json"], capture_output=True, text=True,
                            env={**os.environ, "AWS_EC2_METADATA_DISABLED": "true"}, check=True)
    assert json.loads(result.stdout)["lead_delta"]["summary"]["STILL_OBSERVED"] == 1


def test_changed_positive_iam_finding_membership_requires_false_witness():
    before, after = pair(STALE), pair(STALE)
    after.services["iam"].resources[0].data["statements"] = role(broad_check="AWSH-IAM-002").data["statements"]
    row = rows(before, after, STALE)[0]
    assert row["state"] == "EVIDENCE_CHANGED"
    assert row["evidence_changes"][0]["kind"] == "SUPPORTING_FINDING_ADDED"


@pytest.mark.parametrize("fact", ["urls", "role_policies"])
def test_missing_required_lambda_fact_never_proves_false(fact):
    after = pair(LAMBDA)
    after.services["lambda"].resources[0].data.pop(fact)
    assert rows(pair(LAMBDA), after)[0]["state"] == "UNKNOWN"


def test_non_global_iam_role_cannot_support_confident_delta():
    before, after = pair(STALE), pair(STALE)
    resource = after.services["iam"].resources[0]
    after.services["iam"].resources[0] = replace(resource, region=REGION)
    after.relationships = ()
    assert all(row["state"] == "UNKNOWN" for row in rows(before, after, STALE))


def test_foreign_relationship_role_does_not_fabricate_lead():
    before = pair(EC2)
    after = pair(EC2)
    edge = after.relationships[0]
    target = replace(edge.target, account_id="999999999999", resource_arn="arn:aws:iam::999999999999:role/worker")
    after.relationships = (replace(edge, target=target),)
    row = rows(before, after, EC2)[0]
    assert row["state"] == "UNKNOWN"
    assert row["after"]["assessment"] == "UNKNOWN"


def test_conflicting_bedrock_binding_cannot_prove_false():
    before, after = pair(AI), pair(AI, risky=False)
    after.services["bedrock"].resources[0].data["execution_role_arn"] = f"arn:aws:iam::{ACCOUNT}:role/different"
    row = rows(before, after, AI)[0]
    assert row["state"] == "UNKNOWN"
    assert "EXECUTION_ROLE_BINDING_CONFLICT" in row["after"]["reason_codes"]


def test_support_wording_is_not_a_security_fingerprint(monkeypatch):
    import awsherlock.lead_delta as delta
    original = delta.investigation_leads

    def wording(snapshot, **kwargs):
        document = original(snapshot, **kwargs)
        if snapshot.metadata.scan_id == "wording-only":
            for lead in document["leads"]:
                for statement in lead["observed"]:
                    statement["text"] = "Updated explanatory wording."
                lead["title"] = "Updated explanation"
        return document

    monkeypatch.setattr(delta, "investigation_leads", wording)
    before, after = pair(LAMBDA), pair(LAMBDA)
    after.metadata = replace(after.metadata, scan_id="wording-only")
    row = rows(before, after)[0]
    assert row["state"] == "STILL_OBSERVED"
    assert row["support_comparison"] == "EQUAL"


def test_false_witness_cross_path_conflict_cannot_claim_transition():
    from awsherlock.snapshot import snapshot_from_dict
    before = pair(STALE)
    after = snapshot_from_dict(json.loads(render_snapshot_json(pair(STALE, risky=False)).replace(
        ":role/worker", ":role/new-path/worker")))
    assert rows(before, after, STALE)[0]["state"] == "UNKNOWN"


def test_source_inputs_are_not_mutated():
    before, after = pair(EC2), pair(EC2)
    saved = [render_snapshot_json(value) for value in (before, after)]
    compare_snapshots(before, after, include_leads=True)
    assert saved == [render_snapshot_json(value) for value in (before, after)]


@pytest.mark.parametrize("direction", ["new", "gone"])
def test_agentcore_conflicting_binding_and_edge_blocks_false_witness(direction):
    from awsherlock.snapshot import snapshot_from_dict
    risky, safe = agentcore_snapshot(), agentcore_snapshot(broad=False)
    edge = safe.relationships[0]
    safe.relationships = (replace(edge, target=replace(edge.target, resource_id="different",
        resource_arn=f"arn:aws:iam::{ACCOUNT}:role/different")),)
    safe = snapshot_from_dict(safe.to_dict())  # This is a valid historic snapshot.
    before, after = (safe, risky) if direction == "new" else (risky, safe)
    row = rows(before, after, AI)[0]
    assert row["state"] == "UNKNOWN"
    assert "EXECUTION_ROLE_BINDING_CONFLICT" in row["reason_codes"]


@pytest.mark.parametrize("service", ["bedrock", "agentcore"])
def test_positive_ai_binding_conflict_is_not_equal_support(service):
    before, after = (pair(AI), pair(AI)) if service == "bedrock" else (agentcore_snapshot(), agentcore_snapshot())
    if service == "bedrock":
        after.services["bedrock"].resources[0].data["execution_role_arn"] = f"arn:aws:iam::{ACCOUNT}:role/different"
    else:
        execution_role = role("different", broad_check="none")
        binding = {**after.services["iam"].resources[0].data["identity_bindings"][0],
                   "role_arn": execution_role.resource_arn}
        execution_role.data["identity_bindings"] = [binding]
        after.services["iam"].resources[0].data.pop("identity_bindings")
        after.services["iam"].resources.append(execution_role)
    row = rows(before, after, AI)[0]
    assert row["state"] == "UNKNOWN"
    assert row["support_comparison"] == "UNKNOWN"
    assert "EXECUTION_ROLE_BINDING_CONFLICT" in row["reason_codes"]


def test_multiple_authoritative_agentcore_roles_are_conflicting_not_missing():
    from awsherlock.snapshot import snapshot_from_dict
    before, after = agentcore_snapshot(), agentcore_snapshot()
    execution_role = role("different", broad_check="none")
    execution_role.data["identity_bindings"] = [{
        **after.services["iam"].resources[0].data["identity_bindings"][0],
        "role_arn": execution_role.resource_arn}]
    after.services["iam"].resources.append(execution_role)
    after = snapshot_from_dict(after.to_dict())
    row = rows(before, after, AI)[0]
    assert row["state"] == "UNKNOWN"
    assert "EXECUTION_ROLE_BINDING_CONFLICT" in row["reason_codes"]


def test_unknown_approval_declaration_cannot_falsify_owner_predicate():
    before, after = pair(OWNER), pair(OWNER, risky=False)
    after.services["iam"].resources[0].data["identity_approval"]["status"] = "unknown"
    row = rows(before, after, OWNER)[0]
    assert row["state"] == "UNKNOWN"
    assert "OWNER_DECLARATION_INCOMPLETE" in row["reason_codes"]


@pytest.mark.parametrize("service", ["bedrock", "agentcore"])
def test_authoritative_ai_role_change_is_confirmed_security_support_change(service):
    from awsherlock.snapshot import snapshot_from_dict
    before = pair(AI) if service == "bedrock" else agentcore_snapshot()
    text = render_snapshot_json(before).replace('"worker"', '"different"').replace(
        ":role/worker", ":role/different")
    after = snapshot_from_dict(json.loads(text))
    row = rows(before, after, AI)[0]
    assert row["before"]["lead_id"] == row["after"]["lead_id"]
    assert row["state"] == "EVIDENCE_CHANGED"
    assert row["support_comparison"] == "CHANGED"
    assert row["evidence_changes"][0]["kind"] == "EXECUTION_ROLE_CHANGED"


@pytest.mark.parametrize("direction", ["new", "gone"])
@pytest.mark.parametrize("foreign_arn", [
    f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:other",
    f"arn:aws:lambda:{REGION}:999999999999:function:fn",
    f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:fn",
    f"arn:aws-us-gov:lambda:{REGION}:{ACCOUNT}:function:fn",
])
def test_foreign_lambda_url_cannot_establish_transition(direction, foreign_arn):
    from awsherlock.snapshot import snapshot_from_dict
    valid, inconsistent = pair(LAMBDA), pair(LAMBDA)
    # Keep broad role evidence unchanged: only the foreign URL appears safe.
    inconsistent.services["lambda"].resources[0].data["urls"] = [
        {"arn": foreign_arn, "auth": "AWS_IAM"}]
    inconsistent = snapshot_from_dict(inconsistent.to_dict())
    before, after = (inconsistent, valid) if direction == "new" else (valid, inconsistent)
    row = rows(before, after)[0]
    assert row["state"] == "UNKNOWN"
    assert "LAMBDA_URL_IDENTITY_MISMATCH" in row["reason_codes"]
    assert row["support_comparison"] == "UNKNOWN"
    assert row["evidence_changes"] == []


@pytest.mark.parametrize("changed", [False, True])
@pytest.mark.parametrize("direction", ["before", "after"])
def test_foreign_lambda_url_cannot_establish_positive_support(direction, changed):
    from awsherlock.snapshot import snapshot_from_dict
    valid, inconsistent = pair(LAMBDA), pair(LAMBDA)
    urls = inconsistent.services["lambda"].resources[0].data["urls"]
    # Even one foreign record mixed with valid observations invalidates support.
    foreign = {"arn": f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:other", "auth": "NONE"}
    inconsistent.services["lambda"].resources[0].data["urls"] = [*urls, foreign] if changed else [foreign]
    inconsistent = snapshot_from_dict(inconsistent.to_dict())
    before, after = (inconsistent, valid) if direction == "before" else (valid, inconsistent)
    row = rows(before, after)[0]
    assert row["state"] == "UNKNOWN"
    assert row["support_comparison"] == "UNKNOWN"
    assert row["evidence_changes"] == []


@pytest.mark.parametrize("suffix", ["", ":live", ":alias-with_underscore", ":1", ":$LATEST"])
@pytest.mark.parametrize("direction", ["new", "gone"])
def test_exact_qualified_lambda_url_preserves_valid_transitions(suffix, direction):
    from awsherlock.snapshot import snapshot_from_dict
    risky, safe = pair(LAMBDA), pair(LAMBDA)
    url = safe.services["lambda"].resources[0].data["urls"][0]
    url.update(arn=url["arn"] + suffix, auth="AWS_IAM")
    safe = snapshot_from_dict(safe.to_dict())
    before, after = (safe, risky) if direction == "new" else (risky, safe)
    row = rows(before, after)[0]
    assert row["state"] == ("NEW" if direction == "new" else "NO_LONGER_OBSERVED")


@pytest.mark.parametrize("direction", ["new", "gone"])
def test_shared_role_group_arn_cannot_establish_transition(direction):
    from awsherlock.snapshot import snapshot_from_dict
    from test_leads_v2 import group

    def observation(group_broad):
        narrow_role = role(broad_check="none", stale=True)
        iam_group = replace(group(), resource_arn=narrow_role.resource_arn)
        if not group_broad:
            iam_group.data["attached"] = []
        return snapshot_from_dict(snapshot([narrow_role, iam_group], version=2).to_dict())

    narrow, group_broad = observation(False), observation(True)
    before, after = (narrow, group_broad) if direction == "new" else (group_broad, narrow)
    row = rows(before, after, STALE)[0]
    assert row["state"] == "UNKNOWN"
    assert "AMBIGUOUS_RESOURCE_IDENTITY" in row["reason_codes"]
    assert row["support_comparison"] == "UNKNOWN"
    assert row["evidence_changes"] == []


@pytest.mark.parametrize("other_type", ["group", "role"])
def test_shared_arn_across_distinct_logical_identities_invalidates_support(other_type):
    from awsherlock.snapshot import snapshot_from_dict
    from test_leads_v2 import group
    execution_role = role(stale=True)
    other = group("other") if other_type == "group" else role("other")
    other = replace(other, resource_arn=execution_role.resource_arn)
    ambiguous = snapshot_from_dict(snapshot([execution_role, other], version=2).to_dict())
    valid = snapshot([role(stale=True)], version=2)
    row = rows(valid, ambiguous, STALE)[0]
    assert row["state"] == "UNKNOWN"
    assert "AMBIGUOUS_RESOURCE_IDENTITY" in row["reason_codes"]


@pytest.mark.parametrize("direction", ["new", "gone"])
def test_unique_role_locator_preserves_stale_transitions_with_same_named_group_user(direction):
    from awsherlock.snapshot import snapshot_from_dict
    from test_leads_v2 import group, user
    safe = snapshot_from_dict(snapshot([role(broad_check="none", stale=True), group(), user()], version=2).to_dict())
    risky = snapshot_from_dict(snapshot([role(stale=True), group(), user()], version=2).to_dict())
    before, after = (safe, risky) if direction == "new" else (risky, safe)
    row = rows(before, after, STALE)[0]
    assert row["state"] == ("NEW" if direction == "new" else "NO_LONGER_OBSERVED")
