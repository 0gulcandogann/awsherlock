"""M5 AI workload relationship and correlation contracts."""

from dataclasses import replace
from datetime import datetime, timezone
import json

import pytest

from awsherlock.collectors.common import CollectionResult
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.identity_validation import identity_binding_sort_key, validate_identity_fact
from awsherlock.leads import CORRELATION_RULES, investigation_leads, render_leads_json
from awsherlock.models import (
    Relationship, RelationshipEvidence, RelationshipType, Resource, ResourceRef, ScanMetadata,
)
from awsherlock.relationships import RelationshipError, project_relationships
from awsherlock.snapshot import Snapshot, snapshot_from_dict
from test_identity import ACCOUNT, ROLE, identity_context, snapshot_at
from test_leads_v2 import REGION, group, role, snapshot, user


BEDROCK_AGENT_ID = "ABCDEFGHIJ"
BEDROCK_AGENT_ARN = f"arn:aws:bedrock:{REGION}:{ACCOUNT}:agent/{BEDROCK_AGENT_ID}"
RUNTIME_ID = "RuntimeName-abcdefghij"
RUNTIME_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/{RUNTIME_ID}"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/team/agents/BedrockRole"


def iam_role(*, arn=ROLE_ARN, name="BedrockRole", bindings=()):
    return Resource(
        service="iam", resource_type="role", account_id=arn.split(":")[4], region=None,
        resource_id=name, resource_arn=arn, data={"identity_bindings": list(bindings)},
    )


def bedrock_agent(*, role_arn=ROLE_ARN, partition="aws", account=ACCOUNT, region=REGION):
    arn = f"arn:{partition}:bedrock:{region}:{account}:agent/{BEDROCK_AGENT_ID}"
    return Resource(
        service="bedrock", resource_type="agent", account_id=account, region=region,
        resource_id=BEDROCK_AGENT_ID, resource_arn=arn,
        data={"execution_role_arn": role_arn},
    )


def versioned_agentcore_binding(*, version="2", role_arn=ROLE_ARN, arn=RUNTIME_ARN):
    return {
        "service": "agentcore", "region": REGION, "resource_arn": arn,
        "role_arn": role_arn, "resource_version": version,
    }


def runtime_arn(runtime_id=RUNTIME_ID, *, partition="aws", region=REGION, account=ACCOUNT):
    return f"arn:{partition}:bedrock-agentcore:{region}:{account}:runtime/{runtime_id}"


def test_bedrock_direct_projection_supports_role_paths_and_exact_provenance():
    services = {
        "bedrock": CollectionResult([bedrock_agent()], []),
        "iam": CollectionResult([iam_role()], []),
    }
    edge = project_relationships(services)[0]
    assert edge.source == ResourceRef(
        service="bedrock", resource_type="agent", account_id=ACCOUNT, region=REGION,
        resource_id=BEDROCK_AGENT_ID, resource_arn=BEDROCK_AGENT_ARN,
    )
    assert edge.target.resource_id == "BedrockRole"
    assert edge.target.resource_arn == ROLE_ARN
    assert edge.evidence == (RelationshipEvidence(
        service="bedrock", fact="execution_role_arn", operation="GetAgent",
    ),)


def test_bedrock_direct_and_iam_binding_merge_into_one_edge_with_two_evidence_entries():
    binding = {
        "service": "bedrock", "region": REGION,
        "resource_arn": BEDROCK_AGENT_ARN, "role_arn": ROLE_ARN,
    }
    services = {
        "iam": CollectionResult([iam_role(bindings=(binding,))], []),
        "bedrock": CollectionResult([bedrock_agent()], []),
    }
    first = project_relationships(services)
    second = project_relationships(dict(reversed(list(services.items()))))
    assert first == second
    assert len(first) == 1
    assert first[0].evidence == (
        RelationshipEvidence(service="bedrock", fact="execution_role_arn", operation="GetAgent"),
        RelationshipEvidence(service="iam", fact="identity_bindings", operation=None),
    )


def test_bedrock_conflicting_valid_role_evidence_fails_independent_of_input_order():
    other_arn = f"arn:aws:iam::{ACCOUNT}:role/other"
    binding = {
        "service": "bedrock", "region": REGION,
        "resource_arn": BEDROCK_AGENT_ARN, "role_arn": other_arn,
    }
    values = [iam_role(), iam_role(arn=other_arn, name="other", bindings=(binding,))]
    for ordered in (values, list(reversed(values))):
        services = {
            "iam": CollectionResult(ordered, []),
            "bedrock": CollectionResult([bedrock_agent()], []),
        }
        with pytest.raises(RelationshipError, match="conflicting execution roles"):
            project_relationships(services)


@pytest.mark.parametrize("change", ["source", "target", "account", "region", "missing"])
def test_bedrock_projection_omits_malformed_or_incomplete_positive_evidence(change):
    source = bedrock_agent()
    if change == "source":
        source = replace(source, resource_arn="not-an-arn")
    elif change == "target":
        source.data["execution_role_arn"] = "not-an-arn"
    elif change == "account":
        source.data["execution_role_arn"] = ROLE_ARN.replace(ACCOUNT, "999999999999")
    elif change == "region":
        source = replace(source, resource_arn=BEDROCK_AGENT_ARN.replace(REGION, "us-east-1"))
    else:
        source.data.pop("execution_role_arn")
    assert project_relationships({"bedrock": CollectionResult([source], [])}) == ()


def test_bedrock_projection_accepts_alternate_partition():
    role_arn = f"arn:aws-us-gov:iam::{ACCOUNT}:role/team/BedrockRole"
    source = bedrock_agent(partition="aws-us-gov", region="us-gov-west-1", role_arn=role_arn)
    edge = project_relationships({"bedrock": CollectionResult([source], [])})[0]
    assert edge.source.resource_arn.startswith("arn:aws-us-gov:bedrock:")
    assert edge.target.resource_arn == role_arn


def test_agentcore_versioned_bindings_project_distinct_version_sources_and_legacy_skips():
    legacy = {key: value for key, value in versioned_agentcore_binding().items()
              if key != "resource_version"}
    role_a = iam_role(bindings=(legacy, versioned_agentcore_binding(version="1")))
    role_b_arn = f"arn:aws:iam::{ACCOUNT}:role/RoleB"
    role_b = iam_role(
        arn=role_b_arn, name="RoleB",
        bindings=(versioned_agentcore_binding(version="2", role_arn=role_b_arn),),
    )
    edges = project_relationships({"iam": CollectionResult([role_b, role_a], [])})
    assert [(edge.source.resource_id, edge.source.resource_arn, edge.target.resource_id) for edge in edges] == [
        (f"{RUNTIME_ID}:1", None, "BedrockRole"),
        (f"{RUNTIME_ID}:2", None, "RoleB"),
    ]
    assert all(edge.source.resource_type == "runtime-version" for edge in edges)


def test_identity_binding_validation_accepts_legacy_and_versioned_agentcore_only():
    legacy = {key: value for key, value in versioned_agentcore_binding().items()
              if key != "resource_version"}
    validate_identity_fact("identity_bindings", [legacy, versioned_agentcore_binding()])
    with pytest.raises(ValueError):
        validate_identity_fact("identity_bindings", [{**legacy, "resource_version": "0"}])
    with pytest.raises(ValueError):
        validate_identity_fact("identity_bindings", [{
            **legacy, "service": "bedrock", "resource_version": "2",
        }])


@pytest.mark.parametrize("version", ["", "0", "-1", "01", "V2", "latest", "2.0", "100000", 2])
def test_versioned_agentcore_binding_rejects_invalid_runtime_versions(version):
    with pytest.raises(ValueError):
        validate_identity_fact("identity_bindings", [versioned_agentcore_binding(version=version)])


@pytest.mark.parametrize(
    "binding",
    [
        versioned_agentcore_binding() | {"region": ""},
        versioned_agentcore_binding() | {"region": "   "},
        versioned_agentcore_binding(arn=runtime_arn(region="us-east-1")),
        versioned_agentcore_binding(arn="not-an-arn"),
        versioned_agentcore_binding(role_arn="not-an-arn"),
        versioned_agentcore_binding(role_arn=f"arn:aws:iam::{ACCOUNT}:user/RuntimeRole"),
        versioned_agentcore_binding(role_arn=f"arn:aws:iam::999999999999:role/RuntimeRole"),
        versioned_agentcore_binding(
            arn=runtime_arn(partition="aws-us-gov"),
            role_arn=f"arn:aws:iam::{ACCOUNT}:role/RuntimeRole",
        ),
    ],
)
def test_versioned_agentcore_binding_rejects_inconsistent_or_malformed_arns(binding):
    with pytest.raises(ValueError):
        validate_identity_fact("identity_bindings", [binding])
    role_name = binding["role_arn"].rsplit("/", 1)[-1]
    containing_role = Resource(
        service="iam", resource_type="role", account_id=ACCOUNT, region=None,
        resource_id=role_name, resource_arn=binding["role_arn"],
        data={"identity_bindings": [binding]},
    )
    assert project_relationships({"iam": CollectionResult([containing_role], [])}) == ()


@pytest.mark.parametrize(
    "role_name",
    ["bad:role", "bad role", "", "A" * 65, "rôle"],
)
def test_versioned_agentcore_binding_rejects_invalid_iam_role_names(role_name):
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/{role_name}"
    binding = versioned_agentcore_binding(role_arn=role_arn)
    with pytest.raises(ValueError):
        validate_identity_fact("identity_bindings", [binding])


@pytest.mark.parametrize("role_name", ["bad:role", "A" * 65])
def test_invalid_iam_role_name_cannot_project_agentcore_relationship(role_name):
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/{role_name}"
    binding = versioned_agentcore_binding(role_arn=role_arn)
    containing_role = iam_role(arn=role_arn, name=role_name, bindings=(binding,))
    assert project_relationships({"iam": CollectionResult([containing_role], [])}) == ()


@pytest.mark.parametrize(
    "role_name",
    ["A" * 64, "ValidRole", "team_role-01", "service.role+test", "AZaz09_+=,.@-"],
)
def test_versioned_agentcore_binding_accepts_create_role_name_contract(role_name):
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/{role_name}"
    binding = versioned_agentcore_binding(role_arn=role_arn)
    validate_identity_fact("identity_bindings", [binding])
    containing_role = iam_role(arn=role_arn, name=role_name, bindings=(binding,))
    assert len(project_relationships({"iam": CollectionResult([containing_role], [])})) == 1


@pytest.mark.parametrize(
    "path",
    ["team/agents/", "aws-service-role/example.amazonaws.com/", f"{'p' * 510}/"],
)
def test_versioned_agentcore_binding_accepts_create_role_path_contract(path):
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/{path}RuntimeRole"
    binding = versioned_agentcore_binding(role_arn=role_arn)
    validate_identity_fact("identity_bindings", [binding])
    containing_role = iam_role(arn=role_arn, name="RuntimeRole", bindings=(binding,))
    assert len(project_relationships({"iam": CollectionResult([containing_role], [])})) == 1


@pytest.mark.parametrize("path", ["bad path/", "téam/", f"{'p' * 511}/"])
def test_versioned_agentcore_binding_rejects_invalid_create_role_paths(path):
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/{path}RuntimeRole"
    binding = versioned_agentcore_binding(role_arn=role_arn)
    with pytest.raises(ValueError):
        validate_identity_fact("identity_bindings", [binding])


def test_snapshot_loader_rejects_versioned_binding_with_invalid_role_name():
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/bad:role"
    binding = versioned_agentcore_binding(role_arn=role_arn)
    resource = iam_role(arn=role_arn, name="bad:role", bindings=(binding,))
    metadata = ScanMetadata(
        scan_id="invalid-role", started_at=datetime(2026, 10, 8, tzinfo=timezone.utc),
        account_id=ACCOUNT, region=REGION, version="test",
    )
    value = Snapshot(metadata, {"iam": CollectionResult([resource], [])}, (), 2)
    with pytest.raises(ValueError):
        snapshot_from_dict(value.to_dict())


def test_agentcore_runtime_arn_uses_installed_output_resource_boundary():
    maximum_id = f"{'A' * 48}-abcdefghij"
    first_invalid_id = f"{'A' * 49}-abcdefghij"
    valid = versioned_agentcore_binding(arn=runtime_arn(maximum_id))
    invalid = versioned_agentcore_binding(arn=runtime_arn(first_invalid_id))
    validate_identity_fact("identity_bindings", [valid])
    with pytest.raises(ValueError):
        validate_identity_fact("identity_bindings", [invalid])
    role_resource = iam_role(bindings=(invalid,))
    assert project_relationships({"iam": CollectionResult([role_resource], [])}) == ()


def test_versioned_and_legacy_bindings_roundtrip_without_projection_on_load():
    legacy = {key: value for key, value in versioned_agentcore_binding().items()
              if key != "resource_version"}
    services = {"iam": CollectionResult([
        iam_role(bindings=(legacy, versioned_agentcore_binding())),
    ], [])}
    metadata = ScanMetadata(
        scan_id="m5-bindings", started_at=datetime(2026, 10, 8, tzinfo=timezone.utc),
        account_id=ACCOUNT, region=REGION, version="test",
    )
    value = Snapshot(metadata, services, (), 2)
    restored = snapshot_from_dict(value.to_dict())
    assert restored.schema_version == 2
    assert restored.relationships == ()
    assert restored.services["iam"].resources[0].data["identity_bindings"] == [
        legacy, versioned_agentcore_binding(),
    ]


def test_agentcore_live_binding_passes_inventory_version_to_get(identity_context):
    context, clients, role_data, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, ai_services=True))
    runtime_arn = f"arn:aws:bedrock-agentcore:us-east-1:{ACCOUNT}:runtime/{RUNTIME_ID}"
    clients["bedrock-agentcore-control"].get_paginator.return_value.paginate.return_value = [{
        "agentRuntimes": [{
            "agentRuntimeId": RUNTIME_ID, "agentRuntimeArn": runtime_arn,
            "agentRuntimeVersion": "2",
        }],
    }]
    clients["bedrock-agentcore-control"].get_agent_runtime.return_value = {
        "agentRuntimeId": RUNTIME_ID, "agentRuntimeArn": runtime_arn,
        "agentRuntimeVersion": "2", "roleArn": ROLE,
        "platformVersion": "V2",
        "environmentVariables": {"SECRET": "not-persisted"},
    }
    report = evaluate_snapshot(snapshot_at(context))
    identity = next(item for item in report.identities if item["arn"] == ROLE)
    binding = next(item for item in identity["evidence"]["identity_bindings"]
                   if item["service"] == "agentcore")
    assert binding["resource_version"] == "2"
    assert binding["resource_version"] != "V2"
    clients["bedrock-agentcore-control"].get_agent_runtime.assert_called_once_with(
        agentRuntimeId=RUNTIME_ID, agentRuntimeVersion="2",
    )
    assert "SECRET" not in json.dumps(binding)


def _agentcore_capture(order):
    context, clients, role_data, user_data, pages = identity_context.__wrapped__()
    context = replace(context, identity_options=replace(context.identity_options, ai_services=True))
    summaries = []
    for version in order:
        runtime_id = f"RuntimeName{version}-abcdefghij"
        summaries.append({
            "agentRuntimeId": runtime_id,
            "agentRuntimeArn": (
                f"arn:aws:bedrock-agentcore:us-east-1:{ACCOUNT}:runtime/{runtime_id}"
            ),
            "agentRuntimeVersion": str(version),
        })
    clients["bedrock-agentcore-control"].get_paginator.return_value.paginate.return_value = [{
        "agentRuntimes": summaries,
    }]
    clients["bedrock-agentcore-control"].get_agent_runtime.side_effect = lambda **params: {
        **next(item for item in summaries if item["agentRuntimeId"] == params["agentRuntimeId"]),
        "roleArn": ROLE,
    }
    return snapshot_at(context)


def test_agentcore_binding_and_snapshot_serialization_ignore_inventory_order():
    first = _agentcore_capture((1, 2, 10))
    second = _agentcore_capture((10, 2, 1))
    first_role = next(item for item in first.services["iam"].resources if item.resource_arn == ROLE)
    second_role = next(item for item in second.services["iam"].resources if item.resource_arn == ROLE)
    assert first_role.data["identity_bindings"] == second_role.data["identity_bindings"]
    versions = [item["resource_version"] for item in first_role.data["identity_bindings"]
                if item["service"] == "agentcore"]
    assert versions == ["1", "10", "2"]
    assert len(versions) == 3
    assert first.to_dict() == second.to_dict()
    assert evaluate_snapshot(first).to_dict() == evaluate_snapshot(second).to_dict()


def test_binding_sort_key_is_deterministic_across_services_and_legacy_shapes():
    legacy = {key: value for key, value in versioned_agentcore_binding().items()
              if key != "resource_version"}
    values = [
        versioned_agentcore_binding(version="2"),
        {"service": "bedrock", "region": REGION, "resource_arn": BEDROCK_AGENT_ARN,
         "role_arn": ROLE_ARN},
        legacy,
        versioned_agentcore_binding(version="1"),
        {"service": "lambda", "region": REGION,
         "resource_arn": f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:worker",
         "role_arn": ROLE_ARN},
        {"service": "ec2", "region": REGION,
         "resource_arn": f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0",
         "role_arn": ROLE_ARN},
    ]
    first = sorted(values, key=identity_binding_sort_key)
    second = sorted(reversed(values), key=identity_binding_sort_key)
    assert first == second
    assert [item["service"] for item in first] == [
        "lambda", "ec2", "bedrock", "agentcore", "agentcore", "agentcore",
    ]
    assert [item.get("resource_version") for item in first[-3:]] == [None, "1", "2"]


@pytest.mark.parametrize("field", ["agentRuntimeId", "agentRuntimeArn", "agentRuntimeVersion", "roleArn"])
def test_agentcore_list_get_or_role_identity_mismatch_emits_no_binding(identity_context, field):
    context, clients, role_data, user_data, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, ai_services=True))
    runtime_arn = f"arn:aws:bedrock-agentcore:us-east-1:{ACCOUNT}:runtime/{RUNTIME_ID}"
    clients["bedrock-agentcore-control"].get_paginator.return_value.paginate.return_value = [{
        "agentRuntimes": [{
            "agentRuntimeId": RUNTIME_ID, "agentRuntimeArn": runtime_arn,
            "agentRuntimeVersion": "2",
        }],
    }]
    detail = {
        "agentRuntimeId": RUNTIME_ID, "agentRuntimeArn": runtime_arn,
        "agentRuntimeVersion": "2", "roleArn": ROLE,
    }
    detail[field] = {
        "agentRuntimeId": "OtherRuntime-abcdefghij",
        "agentRuntimeArn": runtime_arn.replace(RUNTIME_ID, "OtherRuntime-abcdefghij"),
        "agentRuntimeVersion": "3",
        "roleArn": ROLE.replace(ACCOUNT, "999999999999"),
    }[field]
    clients["bedrock-agentcore-control"].get_agent_runtime.return_value = detail
    report = evaluate_snapshot(snapshot_at(context))
    identity = next(item for item in report.identities if item["arn"] == ROLE)
    assert report.incomplete
    assert not any(item["service"] == "agentcore"
                   for item in identity["evidence"]["identity_bindings"])


def ai_edge(source, target):
    return Relationship(
        source=source, relationship_type=RelationshipType.RUNS_AS, target=target,
        evidence=(RelationshipEvidence(service="iam", fact="identity_bindings"),),
    )


def test_agentcore_dangling_source_produces_ai_lead_and_versions_have_distinct_ids():
    target = role("worker")
    target_ref = ResourceRef(
        service="iam", resource_type="role", account_id=ACCOUNT, region=None,
        resource_id="worker", resource_arn=target.resource_arn,
    )
    relationships = tuple(ai_edge(ResourceRef(
        service="agentcore", resource_type="runtime-version", account_id=ACCOUNT,
        region=REGION, resource_id=f"{RUNTIME_ID}:{version}", resource_arn=None,
    ), target_ref) for version in ("1", "2"))
    value = snapshot([target], relationships=relationships, version=2)
    matches = [item for item in investigation_leads(value)["leads"]
               if item["pattern_id"] == "AI-WORKLOAD-BROAD-EXECUTION-ROLE"]
    assert len(matches) == 2
    assert {item["subjects"][0]["resource_id"] for item in matches} == {
        f"{RUNTIME_ID}:1", f"{RUNTIME_ID}:2",
    }
    assert len({item["lead_id"] for item in matches}) == 2


def test_ai_lead_exact_role_join_and_complete_json_are_order_independent():
    target = role("worker")
    target.data["statements"] = [{
        "effect": "Allow", "conditional": False, "actions": ["*"], "resources": ["*"],
        "not_actions": False, "not_resources": False,
    }]
    workload = ResourceRef(
        service="bedrock", resource_type="agent", account_id=ACCOUNT, region=REGION,
        resource_id=BEDROCK_AGENT_ID, resource_arn=BEDROCK_AGENT_ARN,
    )
    target_ref = ResourceRef(
        service="iam", resource_type="role", account_id=ACCOUNT, region=None,
        resource_id=target.resource_id, resource_arn=target.resource_arn,
    )
    edge = ai_edge(workload, target_ref)
    first = snapshot([target], relationships=(edge,), version=2)
    second = snapshot([target], relationships=tuple(reversed((edge,))), version=2)
    document = investigation_leads(first)
    matches = [item for item in document["leads"]
               if item["pattern_id"] == "AI-WORKLOAD-BROAD-EXECUTION-ROLE"]
    assert len(matches) == 1
    assert matches[0]["priority"] == "MEDIUM"
    assert {item["check_id"] for item in matches[0]["findings"]} == {
        "AWSH-IAM-001", "AWSH-IAM-002", "AWSH-IAM-003",
    }
    assert render_leads_json(document) == render_leads_json(investigation_leads(second))


def test_ai_lead_skips_v1_wrong_role_and_same_named_user_group():
    target = role("worker", broad_check=None)
    source = ResourceRef(
        service="agentcore", resource_type="runtime-version", account_id=ACCOUNT,
        region=REGION, resource_id=f"{RUNTIME_ID}:2", resource_arn=None,
    )
    target_ref = ResourceRef(
        service="iam", resource_type="role", account_id=ACCOUNT, region=None,
        resource_id="worker", resource_arn=target.resource_arn,
    )
    assert not [item for item in investigation_leads(snapshot([target]))["leads"]
                if item["pattern_id"] == "AI-WORKLOAD-BROAD-EXECUTION-ROLE"]
    assert not [item for item in investigation_leads(snapshot(
        [target], relationships=(ai_edge(source, target_ref),), version=2,
    ))["leads"] if item["pattern_id"] == "AI-WORKLOAD-BROAD-EXECUTION-ROLE"]
    for unrelated in (user("worker"), group("worker")):
        value = snapshot(
            [target, unrelated], relationships=(ai_edge(source, target_ref),), version=2,
        )
        assert not [item for item in investigation_leads(value)["leads"]
                    if item["pattern_id"] == "AI-WORKLOAD-BROAD-EXECUTION-ROLE"]


def test_ai_lead_does_not_join_same_role_name_in_another_account():
    target = role("worker")
    other_account = "999999999999"
    remote_target = ResourceRef(
        service="iam", resource_type="role", account_id=other_account, region=None,
        resource_id="worker", resource_arn=f"arn:aws:iam::{other_account}:role/worker",
    )
    source = ResourceRef(
        service="agentcore", resource_type="runtime-version", account_id=other_account,
        region=REGION, resource_id=f"{RUNTIME_ID}:2", resource_arn=None,
    )
    value = snapshot([target], relationships=(ai_edge(source, remote_target),), version=2)
    assert not [item for item in investigation_leads(value)["leads"]
                if item["pattern_id"] == "AI-WORKLOAD-BROAD-EXECUTION-ROLE"]


@pytest.mark.parametrize(
    ("service", "resource_type"),
    [
        ("lambda", "function"),
        ("ec2", "instance"),
        ("agentcore", "runtime"),
        ("future-ai", "workload"),
    ],
)
def test_ai_lead_rejects_unapproved_relationship_source_types(service, resource_type):
    target = role("worker")
    source = ResourceRef(
        service=service, resource_type=resource_type, account_id=ACCOUNT, region=REGION,
        resource_id="synthetic", resource_arn=None,
    )
    target_ref = ResourceRef(
        service="iam", resource_type="role", account_id=ACCOUNT, region=None,
        resource_id="worker", resource_arn=target.resource_arn,
    )
    value = snapshot([target], relationships=(ai_edge(source, target_ref),), version=2)
    assert not [item for item in investigation_leads(value)["leads"]
                if item["pattern_id"] == "AI-WORKLOAD-BROAD-EXECUTION-ROLE"]


def test_ai_lead_replays_offline_without_aws_clients(monkeypatch):
    target = role("worker")
    source = ResourceRef(
        service="agentcore", resource_type="runtime-version", account_id=ACCOUNT,
        region=REGION, resource_id=f"{RUNTIME_ID}:2", resource_arn=None,
    )
    target_ref = ResourceRef(
        service="iam", resource_type="role", account_id=ACCOUNT, region=None,
        resource_id="worker", resource_arn=target.resource_arn,
    )
    restored = snapshot_from_dict(snapshot(
        [target], relationships=(ai_edge(source, target_ref),), version=2,
    ).to_dict())
    monkeypatch.setattr(
        "awsherlock.aws.context.ScanContext.client",
        lambda *args, **kwargs: pytest.fail("offline replay created an AWS client"),
    )
    matches = [item for item in investigation_leads(restored)["leads"]
               if item["pattern_id"] == "AI-WORKLOAD-BROAD-EXECUTION-ROLE"]
    assert len(matches) == 1


def test_m5_counts_and_rule_registry():
    assert len(CORRELATION_RULES) == 5
    assert CORRELATION_RULES[-1].pattern_id == "AI-WORKLOAD-BROAD-EXECUTION-ROLE"
    assert CORRELATION_RULES[-1].priority.value == "MEDIUM"
