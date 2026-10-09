"""Leads v2 correlation behavior over synthetic offline snapshots."""

import json
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from awsherlock.collectors.common import CollectionResult
from awsherlock.correlation import CorrelationError
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.leads import CORRELATION_RULES, investigation_leads, render_leads_json
from awsherlock.models import (
    Relationship, RelationshipEvidence, RelationshipType, Resource, ResourceRef, ScanMetadata,
)
from awsherlock.snapshot import Snapshot


ACCOUNT = "123456789012"
REGION = "eu-west-1"


def function(name="fn", *, risky=True):
    arn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}"
    return Resource(service="lambda", resource_type="function", account_id=ACCOUNT, region=REGION,
                    resource_id=name, resource_arn=arn, data={
                        "urls": [{"arn": arn, "auth": "NONE" if risky else "AWS_IAM"}],
                        "role_policies": (["arn:aws:iam::aws:policy/AdministratorAccess"]
                                          if risky else []),
                        "runtime": {"name": "python3.13", "deprecated": False,
                                    "catalog_date": "2026-09-15", "evaluated_on": "2026-10-07"},
                    })


def instance(name="i-0123456789abcdef0", *, public=True, imdsv1=True):
    return Resource(service="ec2", resource_type="instance", account_id=ACCOUNT, region=REGION,
                    resource_id=name, resource_arn=f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{name}",
                    data={"metadata": {"endpoint": "enabled", "tokens": "optional" if imdsv1 else "required"},
                          "addresses": ["198.51.100.10"] if public else []})


def role(name="worker", *, broad_check="AWSH-IAM-001", unowned=False, stale=False):
    attached = ["arn:aws:iam::aws:policy/AdministratorAccess"] if broad_check == "AWSH-IAM-001" else []
    statements = []
    if broad_check == "AWSH-IAM-002":
        statements = [{"effect": "Allow", "conditional": False, "actions": ["s3:*"],
                       "resources": ["arn:aws:s3:::example/object"], "not_actions": False,
                       "not_resources": False}]
    if broad_check == "AWSH-IAM-003":
        statements = [{"effect": "Allow", "conditional": False, "actions": ["s3:GetObject"],
                       "resources": ["*"], "not_actions": False, "not_resources": False}]
    return Resource(service="iam", resource_type="role", account_id=ACCOUNT, region=None,
                    resource_id=name, resource_arn=f"arn:aws:iam::{ACCOUNT}:role/{name}", data={
                        "attached": attached, "statements": statements,
                        "identity_requested": True,
                        "identity_profile": {"owner": not unowned, "purpose": True,
                                             "declared_kind": "workload", "boundary": None,
                                             "service_linked": False},
                        "identity_approval": {"status": "registered", "declared_kind": "workload",
                                              "owner": not unowned, "purpose": True,
                                              "allowed_principals": ["lambda.amazonaws.com"], "shared": False,
                                              "external_id_required": False, "source_identity_required": False},
                        "identity_policy_context": {"complete": True, "managed_sources": []},
                        "identity_usage": {"created_days": 200, "last_used_days": 120 if stale else 2,
                                           "status": "recorded"},
                        "identity_trust": {"principals": [{"kind": "Service", "value": "lambda.amazonaws.com"}],
                                           "mechanisms": ["aws_service"], "broad": False,
                                           "status": "supported", "external_id_condition": False,
                                           "source_identity_condition": False},
                    })


def group(name="worker"):
    return Resource(service="iam", resource_type="group", account_id=ACCOUNT, region=None,
                    resource_id=name, resource_arn=f"arn:aws:iam::{ACCOUNT}:group/{name}", data={
                        "attached": ["arn:aws:iam::aws:policy/AdministratorAccess"],
                        "statements": [],
                    })


def user(name="worker", *, broad=True, unowned=True):
    return Resource(service="iam", resource_type="user", account_id=ACCOUNT, region=None,
                    resource_id=name, resource_arn=f"arn:aws:iam::{ACCOUNT}:user/{name}", data={
                        "attached": (["arn:aws:iam::aws:policy/AdministratorAccess"] if broad else []),
                        "statements": [], "console_mfa": {"console": False, "mfa": False},
                        "identity_requested": True,
                        "identity_profile": {"owner": not unowned, "purpose": True,
                                             "declared_kind": "human", "boundary": None,
                                             "service_linked": False},
                        "identity_approval": {"status": "registered", "declared_kind": "human",
                                              "owner": not unowned, "purpose": True,
                                              "allowed_principals": [], "shared": False,
                                              "external_id_required": False, "source_identity_required": False},
                        "identity_policy_context": {"complete": True, "managed_sources": []},
                    })


def ref(item):
    return ResourceRef(service=item.service, resource_type=item.resource_type, account_id=item.account_id,
                       region=item.region, resource_id=item.resource_id, resource_arn=item.resource_arn)


def runs_as(workload, target):
    return Relationship(source=ref(workload), relationship_type=RelationshipType.RUNS_AS,
                        target=ref(target),
                        evidence=(RelationshipEvidence(service="iam", fact="identity_bindings"),))


def snapshot(resources, *, relationships=(), version=1):
    services = {}
    for item in resources:
        services.setdefault(item.service, CollectionResult()).resources.append(item)
    metadata = ScanMetadata(scan_id="leads-v2", started_at=datetime(2026, 10, 7, tzinfo=timezone.utc),
                            account_id=ACCOUNT, region=REGION, version="test")
    return Snapshot(metadata, services, relationships, version)


def leads(value, pattern):
    return [item for item in investigation_leads(value)["leads"] if item["pattern_id"] == pattern]


def test_investigation_leads_can_reuse_exact_pre_evaluated_report():
    value = snapshot([function()], version=2)
    selected = evaluate_snapshot(value, selected_checks=["AWSH-LAMBDA-001"])

    document = investigation_leads(value, report=selected)

    assert [item for item in document["leads"]
            if item["pattern_id"] == "LAMBDA-URL-BROAD-ROLE"] == []
    assert document["coverage"] == selected.coverage


def test_lambda_v1_and_v2_context_have_same_identity():
    workload, execution_role = function(), role()
    legacy = leads(snapshot([workload]), "LAMBDA-URL-BROAD-ROLE")[0]
    current = leads(snapshot([workload, execution_role], relationships=(runs_as(workload, execution_role),),
                             version=2), "LAMBDA-URL-BROAD-ROLE")[0]
    assert legacy["lead_id"] == current["lead_id"]
    assert legacy["relationships"] == []
    assert current["relationships"][0]["type"] == "RUNS_AS"
    without_edge = leads(snapshot([workload], version=2), "LAMBDA-URL-BROAD-ROLE")[0]
    assert without_edge["lead_id"] == legacy["lead_id"]
    assert without_edge["relationships"] == []


@pytest.mark.parametrize("broad_check", ["AWSH-IAM-001", "AWSH-IAM-002", "AWSH-IAM-003"])
def test_ec2_requires_exact_role_broad_signal(broad_check):
    workload, execution_role = instance(), role(broad_check=broad_check)
    lead = leads(snapshot([workload, execution_role], relationships=(runs_as(workload, execution_role),),
                          version=2), "PUBLIC-EC2-IMDSV1-BROAD-ROLE")[0]
    assert {item["check_id"] for item in lead["findings"]} == {
        "AWSH-EC2-004", "AWSH-EC2-005", broad_check,
    }
    assert {item["code"] for item in lead["observed"]} == {
        "EC2_PUBLIC_ADDRESS", "EC2_IMDSV1_ALLOWED", "EC2_RUNS_AS_IAM_ROLE",
        "IAM_BROAD_PERMISSION_FINDING",
    }
    assert {item["code"] for item in lead["unknown"]} == {
        "APPLICATION_REQUEST_PATH_NOT_EVALUATED", "EFFECTIVE_IAM_PERMISSIONS_NOT_EVALUATED",
        "NETWORK_REACHABILITY_NOT_EVALUATED",
    }
    assert {item["code"] for item in lead["not_proven"]} == {
        "ATTACK_PATH_NOT_PROVEN", "COMPROMISE_NOT_PROVEN", "CREDENTIAL_ACCESS_NOT_PROVEN",
        "EFFECTIVE_ACCESS_NOT_PROVEN", "EXPLOITABILITY_NOT_PROVEN",
    }


def test_ec2_skips_v1_missing_edge_and_wrong_role_signal():
    workload, target, broad_other = instance(), role("target", broad_check=None), role("other")
    assert not leads(snapshot([workload, broad_other]), "PUBLIC-EC2-IMDSV1-BROAD-ROLE")
    assert not leads(snapshot([workload, broad_other], version=2), "PUBLIC-EC2-IMDSV1-BROAD-ROLE")
    assert not leads(snapshot([workload, target, broad_other], relationships=(runs_as(workload, target),),
                              version=2), "PUBLIC-EC2-IMDSV1-BROAD-ROLE")


def test_ec2_requires_both_public_address_and_imdsv1_findings():
    target = role()
    for workload in (instance(public=False), instance(imdsv1=False)):
        assert not leads(snapshot([workload, target], relationships=(runs_as(workload, target),), version=2),
                         "PUBLIC-EC2-IMDSV1-BROAD-ROLE")


def test_cross_account_ec2_role_name_does_not_join_local_broad_finding():
    workload, local_role = instance(), role()
    other_account = "999999999999"
    remote_target = ResourceRef(service="iam", resource_type="role", account_id=other_account,
                                region=None, resource_id=local_role.resource_id,
                                resource_arn=f"arn:aws:iam::{other_account}:role/{local_role.resource_id}")
    edge = Relationship(source=ref(workload), relationship_type=RelationshipType.RUNS_AS,
                        target=remote_target,
                        evidence=(RelationshipEvidence(service="iam", fact="identity_bindings"),))
    assert not leads(snapshot([workload, local_role], relationships=(edge,), version=2),
                     "PUBLIC-EC2-IMDSV1-BROAD-ROLE")


def test_ec2_multiple_broad_findings_merge_into_one_lead():
    workload, target = instance(), role()
    target.data["statements"] = [{"effect": "Allow", "conditional": False, "actions": ["*"],
                                  "resources": ["*"], "not_actions": False, "not_resources": False}]
    matches = leads(snapshot([workload, target], relationships=(runs_as(workload, target),), version=2),
                    "PUBLIC-EC2-IMDSV1-BROAD-ROLE")
    assert len(matches) == 1
    assert {item["check_id"] for item in matches[0]["findings"]} >= {
        "AWSH-IAM-001", "AWSH-IAM-002", "AWSH-IAM-003",
    }


def test_unowned_role_merges_multiple_incoming_workloads():
    first, second, target = function("first", risky=False), instance(), role(unowned=True)
    matches = leads(snapshot([first, second, target], relationships=(runs_as(first, target), runs_as(second, target)),
                             version=2), "UNOWNED-BROAD-IAM-WORKLOAD-ROLE")
    assert len(matches) == 1
    assert matches[0]["subjects"][0]["resource_id"] == "worker"
    assert {item["resource_id"] for item in matches[0]["related_resources"]} == {
        "first", "i-0123456789abcdef0",
    }
    assert len(matches[0]["relationships"]) == 2
    assert not leads(snapshot([target], version=2), "UNOWNED-BROAD-IAM-WORKLOAD-ROLE")
    permuted = snapshot([target, second, first], relationships=(runs_as(second, target), runs_as(first, target)),
                        version=2)
    original = investigation_leads(snapshot(
        [first, second, target], relationships=(runs_as(first, target), runs_as(second, target)), version=2,
    ))
    assert original["leads"] == investigation_leads(permuted)["leads"]


def test_unowned_role_ignores_same_named_unowned_user_finding():
    workload, target = function("worker-fn", risky=False), role(unowned=True)
    same_named_user = user(target.resource_id, broad=False, unowned=True)
    matches = leads(snapshot([workload, target, same_named_user], relationships=(runs_as(workload, target),),
                             version=2), "UNOWNED-BROAD-IAM-WORKLOAD-ROLE")
    assert len(matches) == 1
    iam_007 = [item for item in matches[0]["findings"] if item["check_id"] == "AWSH-IAM-007"]
    assert len(iam_007) == 1
    assert iam_007[0]["resource_arn"] == target.resource_arn


def test_unowned_role_does_not_consume_same_named_user_or_group_broad_findings():
    workload = function("worker-fn", risky=False)
    target = role(unowned=True, broad_check=None)
    for unrelated in (user(target.resource_id, broad=True, unowned=True), group(target.resource_id)):
        assert not leads(snapshot([workload, target, unrelated], relationships=(runs_as(workload, target),),
                                  version=2), "UNOWNED-BROAD-IAM-WORKLOAD-ROLE")


def test_stale_role_merges_all_broad_findings_in_v1():
    target = role(stale=True)
    target.data["statements"] = [{"effect": "Allow", "conditional": False, "actions": ["*"],
                                  "resources": ["*"], "not_actions": False, "not_resources": False}]
    matches = leads(snapshot([target]), "STALE-BROAD-IAM-ROLE")
    assert len(matches) == 1
    assert {item["check_id"] for item in matches[0]["findings"]} == {
        "AWSH-IAM-001", "AWSH-IAM-002", "AWSH-IAM-003", "AWSH-IAM-009",
    }
    assert not leads(snapshot([role(stale=True, broad_check=None)]), "STALE-BROAD-IAM-ROLE")
    assert not leads(snapshot([role(stale=False)]), "STALE-BROAD-IAM-ROLE")
    assert len(leads(snapshot([target], version=2), "STALE-BROAD-IAM-ROLE")) == 1


def test_same_named_iam_group_broad_finding_does_not_correlate_to_role():
    stale_role = role(stale=True, broad_check=None)
    assert not leads(snapshot([stale_role, group(stale_role.resource_id)]), "STALE-BROAD-IAM-ROLE")
    assert not leads(snapshot([stale_role, user(stale_role.resource_id)]), "STALE-BROAD-IAM-ROLE")


def test_lead_generation_is_neutral_and_order_independent():
    workload, target = instance(), role(stale=True, unowned=True)
    edge = runs_as(workload, target)
    original = snapshot([workload, target], relationships=(edge,), version=2)
    permuted = Snapshot(original.metadata, {"iam": original.services["iam"], "ec2": original.services["ec2"]},
                        tuple(reversed(original.relationships)), 2)
    before = evaluate_snapshot(original).to_dict()
    assert json.loads(render_leads_json(investigation_leads(original)))["leads"] == json.loads(
        render_leads_json(investigation_leads(permuted)))["leads"]
    assert evaluate_snapshot(original).to_dict() == before
    assert original.relationships == (edge,)


def test_complete_leads_json_is_service_order_independent():
    workload, target = instance(), role(stale=True, unowned=True)
    first = snapshot([workload, target], relationships=(runs_as(workload, target),), version=2)
    second = Snapshot(first.metadata, dict(reversed(list(first.services.items()))),
                      tuple(reversed(first.relationships)), 2)
    assert render_leads_json(investigation_leads(first)) == render_leads_json(investigation_leads(second))


def test_snapshot_is_evaluated_once_and_registry_is_exact(monkeypatch):
    value = snapshot([function()])
    original = evaluate_snapshot
    calls = []

    def counted(snapshot_value):
        calls.append(snapshot_value)
        return original(snapshot_value)

    monkeypatch.setattr("awsherlock.leads.evaluate_snapshot", counted)
    document = investigation_leads(value)
    assert calls == [value]
    assert document["source_snapshot"] == {
        "scan_id": "leads-v2", "schema_version": 1, "supports_relationships": False,
    }
    assert [rule.pattern_id for rule in CORRELATION_RULES] == [
        "LAMBDA-URL-BROAD-ROLE", "PUBLIC-EC2-IMDSV1-BROAD-ROLE",
        "UNOWNED-BROAD-IAM-WORKLOAD-ROLE", "STALE-BROAD-IAM-ROLE",
        "AI-WORKLOAD-BROAD-EXECUTION-ROLE",
    ]
    assert [rule.priority.value for rule in CORRELATION_RULES] == [
        "HIGH", "HIGH", "MEDIUM", "MEDIUM", "MEDIUM",
    ]


def test_rule_registry_metadata_must_match_emitted_leads(monkeypatch):
    mismatched = replace(CORRELATION_RULES[0], title="Conflicting title")
    monkeypatch.setattr("awsherlock.leads.CORRELATION_RULES", (mismatched,))
    with pytest.raises(CorrelationError, match="metadata"):
        investigation_leads(snapshot([function()]))
