"""Amazon Bedrock configuration evidence and deterministic offline rules."""

from datetime import datetime, timezone
import json
from types import SimpleNamespace
from unittest.mock import Mock

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from botocore.stub import Stubber

from awsherlock.collectors.bedrock import collect_bedrock
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.leads import CORRELATION_RULES
from awsherlock.models import Resource, ScanMetadata, Severity
from awsherlock.registry import SERVICE_SPECS, check_specs, service_spec
from awsherlock.reporting import render_html, render_json
from awsherlock.sarif import render_sarif
from awsherlock.scanner import DEFAULT_SERVICES, parse_services
from awsherlock.snapshot import Snapshot, SnapshotError, snapshot_from_dict


ACCOUNT = "123456789012"
OTHER_ACCOUNT = "999999999999"
REGION = "eu-west-1"
AGENT_A = "ABCDEFGHIJ"
AGENT_B = "KLMNOPQRST"


def aws_error(code: str, operation: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "sensitive-service-message"}}, operation)


class Pages:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self):
        for page in self.pages:
            if isinstance(page, Exception):
                raise page
            yield page


class AgentClient:
    def __init__(self, pages, details=None):
        self.pages = pages
        self.details = details or {}
        self.requested = []

    def get_paginator(self, operation):
        assert operation == "list_agents"
        return Pages(self.pages)

    def get_agent(self, *, agentId):
        self.requested.append(agentId)
        value = self.details[agentId]
        if isinstance(value, Exception):
            raise value
        return value


class BedrockClient:
    def __init__(self, response):
        self.response = response
        self.calls = 0

    def get_model_invocation_logging_configuration(self):
        self.calls += 1
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def active_logging(*, destination="cloudwatch", modality="text"):
    config = {f"{modality}DataDeliveryEnabled": True}
    if destination == "cloudwatch":
        config["cloudWatchConfig"] = {
            "logGroupName": "/aws/bedrock/modelinvocations",
            "roleArn": f"arn:aws:iam::{ACCOUNT}:role/BedrockLoggingRole",
        }
    elif destination == "s3":
        config["s3Config"] = {"bucketName": "synthetic-bedrock-logs", "keyPrefix": "logs/"}
    return {"loggingConfig": config}


def agent_detail(agent_id=AGENT_A, *, status="PREPARED", guardrail="absent",
                 account=ACCOUNT, arn_agent_id=None, version="DRAFT"):
    arn_agent_id = arn_agent_id or agent_id
    detail = {
        "agentId": agent_id,
        "agentArn": f"arn:aws:bedrock:{REGION}:{account}:agent/{arn_agent_id}",
        "agentVersion": version,
        "agentStatus": status,
        "agentResourceRoleArn": f"arn:aws:iam::{account}:role/BedrockAgentRole-{agent_id}",
        "instruction": "prompt-secret-marker",
        "description": "description-secret-marker",
        "failureReasons": ["failure-secret-marker"],
    }
    if guardrail != "absent":
        detail["guardrailConfiguration"] = guardrail
    return {"agent": detail}


def collect(agent_client, bedrock_client, *, region=REGION):
    calls = []

    def get_client(service, **options):
        calls.append((service, options))
        assert options == {"region_name": region}
        return {"bedrock-agent": agent_client, "bedrock": bedrock_client}[service]

    context = SimpleNamespace(account_id=ACCOUNT, partition="aws", region=region,
                              client=get_client)
    return collect_bedrock(context), calls


def snapshot_for(result):
    metadata = ScanMetadata(scan_id="bedrock-test", started_at=datetime.now(timezone.utc),
                            account_id=ACCOUNT, region=REGION, version="test")
    return Snapshot(metadata, {"bedrock": result}, (), 2)


def report_for(result, **options):
    snapshot = snapshot_for(result)
    return evaluate_snapshot(snapshot, **options), snapshot


def finding_ids(report):
    return [finding.id for finding in report.findings]


def test_missing_region_does_not_create_clients():
    context = SimpleNamespace(account_id=ACCOUNT, partition="aws", region=None,
                              client=Mock(side_effect=AssertionError("no client")))
    result = collect_bedrock(context)
    assert result.resources == [] and result.completed_operations == []
    assert [(issue.operation, issue.message) for issue in result.issues] == [
        ("Region", "Configure an AWS region for Amazon Bedrock")
    ]
    context.client.assert_not_called()


def test_empty_agent_inventory_and_absent_runtime_logging_are_definitive():
    result, calls = collect(AgentClient([{"agentSummaries": []}]), BedrockClient({}))
    report, _ = report_for(result)
    assert calls == [
        ("bedrock", {"region_name": REGION}),
        ("bedrock-agent", {"region_name": REGION}),
    ]
    assert result.completed_operations == ["ListAgents"]
    assert [resource.resource_type for resource in result.resources] == ["regional-settings"]
    assert result.resources[0].data == {
        "model_invocation_logging_configuration": {
            "configured": False, "destinations": [], "modalities": [],
        }
    }
    assert finding_ids(report) == ["AWSH-BEDROCK-002"]
    assert report.findings[0].severity is Severity.LOW
    assert report.coverage[0]["status"] == "COMPLETE"


def test_agent_without_guardrail_is_draft_scoped_and_sensitive_fields_are_not_stored():
    agents = AgentClient([{"agentSummaries": [{"agentId": AGENT_A}]}],
                         {AGENT_A: agent_detail()})
    result, _ = collect(agents, BedrockClient(active_logging()))
    report, _ = report_for(result)
    resource = next(item for item in result.resources if item.resource_type == "agent")
    assert resource.resource_id == AGENT_A
    assert resource.resource_arn == f"arn:aws:bedrock:{REGION}:{ACCOUNT}:agent/{AGENT_A}"
    assert resource.data == {
        "agent_status": "PREPARED",
        "agent_version": "DRAFT",
        "execution_role_arn": f"arn:aws:iam::{ACCOUNT}:role/BedrockAgentRole-{AGENT_A}",
        "guardrail_configuration": {"identifier": None, "version": None},
    }
    serialized = json.dumps(resource.data)
    assert all(marker not in serialized for marker in (
        "prompt-secret-marker", "description-secret-marker", "failure-secret-marker",
    ))
    assert finding_ids(report) == ["AWSH-BEDROCK-001"]
    finding = report.findings[0]
    assert "DRAFT" in finding.title and "DRAFT" in finding.description
    assert "deployed" not in finding.description.lower()
    assert "exploitable" not in finding.description.lower()


@pytest.mark.parametrize("status", [
    "CREATING", "PREPARING", "PREPARED", "NOT_PREPARED", "UPDATING",
    "VERSIONING", "FAILED", "DELETING",
])
def test_agent_lifecycle_does_not_suppress_valid_guardrail_evaluation(status):
    guardrail = {"guardrailIdentifier": "guardrail123", "guardrailVersion": "1"}
    result, _ = collect(
        AgentClient([{"agentSummaries": [{"agentId": AGENT_A}]}],
                    {AGENT_A: agent_detail(status=status, guardrail=guardrail)}),
        BedrockClient(active_logging()),
    )
    report, _ = report_for(result)
    agent = next(item for item in result.resources if item.resource_type == "agent")
    assert agent.data["agent_status"] == status
    assert agent.data["guardrail_configuration"] == {
        "identifier": "guardrail123", "version": "1",
    }
    assert "AWSH-BEDROCK-001" not in finding_ids(report)
    assert report.coverage[0]["status"] == "COMPLETE"


@pytest.mark.parametrize("guardrail", [
    {"identifier": "guardrail123", "version": "1"},
    {"identifier": None, "version": None},
])
def test_snapshot_rejects_guardrail_evidence_detached_from_draft_context(guardrail):
    result, _ = collect(
        AgentClient([{"agentSummaries": [{"agentId": AGENT_A}]}], {AGENT_A: agent_detail()}),
        BedrockClient(active_logging()),
    )
    raw = snapshot_for(result).to_dict()
    data = next(resource["data"] for resource in raw["services"]["bedrock"]["resources"]
                if resource["resource_type"] == "agent")
    data.clear()
    data["guardrail_configuration"] = guardrail
    with pytest.raises(SnapshotError):
        snapshot_from_dict(raw)


def test_guardrail_rule_defensively_requires_draft_context_and_preserves_valid_results():
    rule = service_spec("bedrock").evaluators[0]
    detached = Resource(
        service="bedrock", resource_type="agent", account_id=ACCOUNT, region=REGION,
        resource_id=AGENT_A, resource_arn=None,
        data={"guardrail_configuration": {"identifier": "guardrail123", "version": "1"}},
    )
    with pytest.raises(ValueError, match="DRAFT"):
        rule.evaluate(detached)

    guarded = Resource(
        service="bedrock", resource_type="agent", account_id=ACCOUNT, region=REGION,
        resource_id=AGENT_A, resource_arn=None,
        data={
            "agent_version": "DRAFT",
            "guardrail_configuration": {"identifier": "guardrail123", "version": "1"},
        },
    )
    unguarded = Resource(
        service="bedrock", resource_type="agent", account_id=ACCOUNT, region=REGION,
        resource_id=AGENT_A, resource_arn=None,
        data={
            "agent_version": "DRAFT",
            "guardrail_configuration": {"identifier": None, "version": None},
        },
    )
    assert rule.evaluate(guarded) == []
    assert [finding.id for finding in rule.evaluate(unguarded)] == ["AWSH-BEDROCK-001"]


@pytest.mark.parametrize("response", [
    {"loggingConfig": {"cloudWatchConfig": {
        "logGroupName": "/aws/bedrock/modelinvocations",
        "roleArn": f"arn:aws:iam::{ACCOUNT}:role/LoggingRole",
    }}},
    {"loggingConfig": {"textDataDeliveryEnabled": True}},
    {"loggingConfig": {}},
])
def test_valid_but_inert_runtime_logging_configuration_is_a_finding(response):
    result, _ = collect(AgentClient([{"agentSummaries": []}]), BedrockClient(response))
    report, _ = report_for(result)
    fact = result.resources[0].data["model_invocation_logging_configuration"]
    assert fact["configured"] is True
    assert "AWSH-BEDROCK-002" in finding_ids(report)
    finding = next(item for item in report.findings if item.id == "AWSH-BEDROCK-002")
    assert "Bedrock Runtime" in finding.title
    assert "does not assess logging or observability for every Bedrock inference endpoint" in finding.description
    assert "all Bedrock invocation activity is unlogged" not in finding.description


@pytest.mark.parametrize(("destination", "modality"), [
    ("cloudwatch", "text"), ("s3", "image"), ("s3", "embedding"),
    ("cloudwatch", "video"), ("cloudwatch", "audio"),
])
def test_active_runtime_logging_configuration_passes(destination, modality):
    result, _ = collect(AgentClient([{"agentSummaries": []}]),
                        BedrockClient(active_logging(destination=destination, modality=modality)))
    report, _ = report_for(result)
    assert "AWSH-BEDROCK-002" not in finding_ids(report)
    assert report.coverage[0]["status"] == "COMPLETE"


def test_logging_destinations_and_modalities_are_canonical_without_identifiers():
    response = {"loggingConfig": {
        "s3Config": {"bucketName": "private-sensitive-bucket", "keyPrefix": "private-prefix"},
        "cloudWatchConfig": {
            "logGroupName": "/private/log/group",
            "roleArn": f"arn:aws:iam::{ACCOUNT}:role/PrivateLoggingRole",
        },
        "videoDataDeliveryEnabled": True,
        "textDataDeliveryEnabled": True,
        "audioDataDeliveryEnabled": False,
        "imageDataDeliveryEnabled": True,
        "embeddingDataDeliveryEnabled": False,
    }}
    result, _ = collect(AgentClient([{"agentSummaries": []}]), BedrockClient(response))
    fact = result.resources[0].data["model_invocation_logging_configuration"]
    assert fact == {
        "configured": True,
        "destinations": ["cloudwatch", "s3"],
        "modalities": ["image", "text", "video"],
    }
    serialized = json.dumps(fact)
    assert all(value not in serialized for value in (
        "private-sensitive-bucket", "private-prefix", "/private/log/group", "PrivateLoggingRole",
    ))


def test_cloudwatch_large_data_s3_is_not_a_top_level_s3_destination():
    response = {"loggingConfig": {
        "cloudWatchConfig": {
            "logGroupName": "/aws/bedrock/modelinvocations",
            "roleArn": f"arn:aws:iam::{ACCOUNT}:role/LoggingRole",
            "largeDataDeliveryS3Config": {
                "bucketName": "large-payloads",
                "keyPrefix": "bedrock/",
            },
        },
        "textDataDeliveryEnabled": True,
    }}
    result, _ = collect(AgentClient([{"agentSummaries": []}]), BedrockClient(response))
    assert result.resources[0].data["model_invocation_logging_configuration"] == {
        "configured": True,
        "destinations": ["cloudwatch"],
        "modalities": ["text"],
    }


@pytest.mark.parametrize("response", [
    {"loggingConfig": "enabled"},
    {"loggingConfig": {"textDataDeliveryEnabled": "true"}},
    {"loggingConfig": {"s3Config": {"bucketName": 1}, "textDataDeliveryEnabled": True}},
    {"loggingConfig": {"cloudWatchConfig": {"logGroupName": "missing-role"},
                       "textDataDeliveryEnabled": True}},
])
def test_malformed_runtime_logging_is_incomplete_not_a_finding(response):
    result, _ = collect(AgentClient([{"agentSummaries": []}]), BedrockClient(response))
    report, _ = report_for(result)
    assert "model_invocation_logging_configuration" not in result.resources[0].data
    assert "AWSH-BEDROCK-002" not in finding_ids(report)
    assert report.coverage[0]["status"] != "COMPLETE"
    assert any(issue.operation == "GetModelInvocationLoggingConfiguration" for issue in result.issues)


def test_multiple_agents_paginate_sort_and_duplicate_or_malformed_ids_are_issues():
    pages = [
        {"agentSummaries": [{"agentId": AGENT_B}, {"agentId": "bad"}]},
        {"agentSummaries": [{"agentId": AGENT_A}, {"agentId": AGENT_B}]},
    ]
    details = {AGENT_A: agent_detail(AGENT_A), AGENT_B: agent_detail(AGENT_B)}
    result, _ = collect(AgentClient(pages, details), BedrockClient(active_logging()))
    agents = [resource for resource in result.resources if resource.resource_type == "agent"]
    assert [resource.resource_id for resource in agents] == [AGENT_A, AGENT_B]
    assert result.completed_operations == ["ListAgents"]
    assert sum(issue.operation == "ListAgents" for issue in result.issues) == 2


def test_agent_issue_order_is_canonical_across_equivalent_summary_permutations():
    details = {AGENT_A: agent_detail(AGENT_A), AGENT_B: agent_detail(AGENT_B)}
    first, _ = collect(AgentClient([{"agentSummaries": [
        {"agentId": AGENT_A}, {"agentId": AGENT_B},
        {"agentId": AGENT_A}, {"agentId": AGENT_B},
    ]}], details), BedrockClient(active_logging()))
    second, _ = collect(AgentClient([{"agentSummaries": [
        {"agentId": AGENT_B}, {"agentId": AGENT_A},
        {"agentId": AGENT_B}, {"agentId": AGENT_A},
    ]}], details), BedrockClient(active_logging()))

    first_snapshot = snapshot_for(first)
    second_snapshot = Snapshot(first_snapshot.metadata, {"bedrock": second}, (), 2)
    assert first.resources == second.resources
    assert first.issues == second.issues
    assert first.completed_operations == second.completed_operations
    assert first_snapshot.to_dict() == second_snapshot.to_dict()
    assert evaluate_snapshot(first_snapshot).coverage == evaluate_snapshot(second_snapshot).coverage


@pytest.mark.parametrize("failure", [
    aws_error("AccessDeniedException", "GetAgent"),
    aws_error("ResourceNotFoundException", "GetAgent"),
])
def test_failed_get_agent_retains_skeleton_and_is_incomplete(failure):
    result, _ = collect(
        AgentClient([{"agentSummaries": [{"agentId": AGENT_A}]}], {AGENT_A: failure}),
        BedrockClient(active_logging()),
    )
    report, _ = report_for(result)
    agent = next(item for item in result.resources if item.resource_type == "agent")
    assert agent.resource_id == AGENT_A and agent.resource_arn is None and agent.data == {}
    assert "AWSH-BEDROCK-001" not in finding_ids(report)
    assert report.coverage[0]["status"] == "PARTIAL"


@pytest.mark.parametrize("detail", [
    agent_detail(agent_id=AGENT_B),
    agent_detail(account=OTHER_ACCOUNT),
    agent_detail(arn_agent_id=AGENT_B),
    agent_detail(version="1"),
    agent_detail(guardrail={"guardrailIdentifier": "guardrail123"}),
    agent_detail(guardrail={"guardrailIdentifier": 1, "guardrailVersion": "1"}),
])
def test_inconsistent_agent_identity_version_or_guardrail_is_incomplete(detail):
    result, _ = collect(
        AgentClient([{"agentSummaries": [{"agentId": AGENT_A}]}], {AGENT_A: detail}),
        BedrockClient(active_logging()),
    )
    report, _ = report_for(result)
    agent = next(item for item in result.resources if item.resource_type == "agent")
    assert agent.resource_arn is None and agent.data == {}
    assert "AWSH-BEDROCK-001" not in finding_ids(report)
    assert report.coverage[0]["status"] == "PARTIAL"


def test_partial_listing_retains_agents_without_completion_marker():
    pages = [
        {"agentSummaries": [{"agentId": AGENT_A}]},
        aws_error("ThrottlingException", "ListAgents"),
    ]
    result, _ = collect(AgentClient(pages, {AGENT_A: agent_detail()}),
                        BedrockClient(active_logging()))
    report, _ = report_for(result)
    assert any(resource.resource_id == AGENT_A for resource in result.resources)
    assert result.completed_operations == []
    assert "AWSH-BEDROCK-001" in finding_ids(report)
    assert report.coverage[0]["status"] == "PARTIAL"


def test_logging_and_agent_failures_are_independent():
    logging_denied, _ = collect(
        AgentClient([{"agentSummaries": [{"agentId": AGENT_A}]}], {AGENT_A: agent_detail()}),
        BedrockClient(aws_error("AccessDeniedException", "GetModelInvocationLoggingConfiguration")),
    )
    report, _ = report_for(logging_denied)
    assert finding_ids(report) == ["AWSH-BEDROCK-001"]
    assert report.coverage[0]["status"] == "PARTIAL"


def test_selected_logging_check_ignores_agent_collection_failure():
    result, _ = collect(
        AgentClient([aws_error("AccessDeniedException", "ListAgents")]),
        BedrockClient({}),
    )
    report, _ = report_for(result, selected_checks=["AWSH-BEDROCK-002"])
    assert finding_ids(report) == ["AWSH-BEDROCK-002"]
    assert report.coverage[0]["status"] == "COMPLETE"
    assert report.incomplete is False


def test_selected_guardrail_check_ignores_logging_collection_failure():
    result, _ = collect(
        AgentClient([{"agentSummaries": [{"agentId": AGENT_A}]}], {AGENT_A: agent_detail()}),
        BedrockClient(aws_error("AccessDeniedException", "GetModelInvocationLoggingConfiguration")),
    )
    report, _ = report_for(result, selected_checks=["AWSH-BEDROCK-001"])
    assert finding_ids(report) == ["AWSH-BEDROCK-001"]
    assert report.coverage[0]["status"] == "COMPLETE"
    assert report.incomplete is False


def test_selected_guardrail_check_preserves_relevant_agent_failure():
    result, _ = collect(
        AgentClient([aws_error("AccessDeniedException", "ListAgents")]),
        BedrockClient(active_logging()),
    )
    report, _ = report_for(result, selected_checks=["AWSH-BEDROCK-001"])
    assert report.incomplete is True
    assert report.coverage[0]["status"] == "ACCESS_DENIED"


def test_selected_logging_check_preserves_relevant_logging_failure():
    result, _ = collect(
        AgentClient([{"agentSummaries": []}]),
        BedrockClient(aws_error("AccessDeniedException", "GetModelInvocationLoggingConfiguration")),
    )
    report, _ = report_for(result, selected_checks=["AWSH-BEDROCK-002"])
    assert report.incomplete is True
    assert report.coverage[0]["status"] == "ACCESS_DENIED"


@pytest.mark.parametrize("failed_family", ["agents", "logging"])
def test_both_selected_bedrock_checks_preserve_either_family_failure(failed_family):
    agents = (AgentClient([aws_error("AccessDeniedException", "ListAgents")])
              if failed_family == "agents" else AgentClient([{"agentSummaries": []}]))
    logging = (BedrockClient(aws_error(
        "AccessDeniedException", "GetModelInvocationLoggingConfiguration",
    )) if failed_family == "logging" else BedrockClient({}))
    result, _ = collect(agents, logging)
    report, _ = report_for(result, selected_checks=[
        "AWSH-BEDROCK-001", "AWSH-BEDROCK-002",
    ])
    assert report.incomplete is True
    assert report.coverage[0]["status"] in {"PARTIAL", "ACCESS_DENIED"}

    agents_denied, _ = collect(
        AgentClient([aws_error("AccessDeniedException", "ListAgents")]),
        BedrockClient({}),
    )
    report, _ = report_for(agents_denied)
    assert finding_ids(report) == ["AWSH-BEDROCK-002"]
    assert report.coverage[0]["status"] == "PARTIAL"


def test_unsupported_region_endpoint_failures_never_become_passes():
    unavailable = EndpointConnectionError(endpoint_url="https://bedrock.invalid")
    result, _ = collect(AgentClient([unavailable]), BedrockClient(unavailable))
    report, _ = report_for(result)
    assert finding_ids(report) == []
    assert report.coverage[0]["status"] == "ERROR"
    assert {issue.operation for issue in result.issues} == {
        "GetModelInvocationLoggingConfiguration", "ListAgents",
    }
    assert all(issue.message == "AWS endpoint connection failed" for issue in result.issues)


def test_missing_inventory_marker_does_not_block_selected_logging_check():
    result, _ = collect(AgentClient([{"agentSummaries": []}]), BedrockClient({}))
    result.completed_operations.clear()
    report, _ = report_for(result, selected_checks=["AWSH-BEDROCK-002"])
    assert finding_ids(report) == ["AWSH-BEDROCK-002"]
    assert not any(issue["operation"] == "RequiredCollection" for issue in report.coverage[0]["issues"])


def test_execution_role_path_is_preserved():
    detail = agent_detail()
    detail["agent"]["agentResourceRoleArn"] = (
        f"arn:aws:iam::{ACCOUNT}:role/team/agents/BedrockRole"
    )
    result, _ = collect(
        AgentClient([{"agentSummaries": [{"agentId": AGENT_A}]}], {AGENT_A: detail}),
        BedrockClient(active_logging()),
    )
    agent = next(resource for resource in result.resources if resource.resource_type == "agent")
    assert agent.data["execution_role_arn"] == (
        f"arn:aws:iam::{ACCOUNT}:role/team/agents/BedrockRole"
    )


def test_collector_matches_installed_botocore_request_and_response_contract():
    session = boto3.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION,
    )
    agent_client = session.client("bedrock-agent")
    bedrock_client = session.client("bedrock")
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    agent_response = {
        "agent": {
            "agentId": AGENT_A,
            "agentName": "agent-a",
            "agentArn": f"arn:aws:bedrock:{REGION}:{ACCOUNT}:agent/{AGENT_A}",
            "agentVersion": "DRAFT",
            "agentStatus": "PREPARED",
            "idleSessionTTLInSeconds": 600,
            "agentResourceRoleArn": f"arn:aws:iam::{ACCOUNT}:role/BedrockRole",
            "createdAt": now,
            "updatedAt": now,
        },
    }
    with Stubber(agent_client) as agent_stub, Stubber(bedrock_client) as bedrock_stub:
        bedrock_stub.add_response(
            "get_model_invocation_logging_configuration", active_logging(), {},
        )
        agent_stub.add_response("list_agents", {"agentSummaries": [{
            "agentId": AGENT_A,
            "agentName": "agent-a",
            "agentStatus": "PREPARED",
            "updatedAt": now,
        }]}, {})
        agent_stub.add_response("get_agent", agent_response, {"agentId": AGENT_A})

        context = SimpleNamespace(
            account_id=ACCOUNT,
            partition="aws",
            region=REGION,
            client=lambda service, **_: {
                "bedrock-agent": agent_client,
                "bedrock": bedrock_client,
            }[service],
        )
        result = collect_bedrock(context)

    assert result.issues == []
    assert result.completed_operations == ["ListAgents"]


def test_snapshot_roundtrip_offline_reports_and_no_relationships(monkeypatch):
    result, _ = collect(
        AgentClient([{"agentSummaries": [{"agentId": AGENT_A}]}], {AGENT_A: agent_detail()}),
        BedrockClient({}),
    )
    live_report, snapshot = report_for(result)
    raw = snapshot.to_dict()
    assert raw["schema_version"] == 2 and raw["relationships"] == []
    assert raw["services"]["bedrock"]["completed_operations"] == ["ListAgents"]
    replay = snapshot_from_dict(raw)
    factory = Mock(side_effect=AssertionError("offline replay created an AWS client"))
    monkeypatch.setattr("awsherlock.aws.context.ScanContext.client", factory)
    offline_report = evaluate_snapshot(replay)
    assert [finding.to_dict() for finding in offline_report.findings] == [
        finding.to_dict() for finding in live_report.findings
    ]
    assert offline_report.coverage == live_report.coverage
    assert replay.relationships == () and len(CORRELATION_RULES) == 5
    factory.assert_not_called()
    for rendered in (render_json(offline_report), render_sarif(offline_report), render_html(offline_report)):
        assert "AWSH-BEDROCK-001" in rendered and "AWSH-BEDROCK-002" in rendered


@pytest.mark.parametrize("mutate", [
    lambda data: data.update({"agent_version": "1"}),
    lambda data: data.update({"agent_status": "UNKNOWN"}),
    lambda data: data.update({"execution_role_arn": "arn:aws:iam::999999999999:role/wrong"}),
    lambda data: data.update({"guardrail_configuration": {"identifier": None, "version": "1"}}),
])
def test_snapshot_rejects_invalid_agent_facts(mutate):
    result, _ = collect(
        AgentClient([{"agentSummaries": [{"agentId": AGENT_A}]}], {AGENT_A: agent_detail()}),
        BedrockClient(active_logging()),
    )
    raw = snapshot_for(result).to_dict()
    data = next(resource["data"] for resource in raw["services"]["bedrock"]["resources"]
                if resource["resource_type"] == "agent")
    mutate(data)
    with pytest.raises(Exception):
        snapshot_from_dict(raw)


@pytest.mark.parametrize("fact", [
    {"configured": "true", "destinations": [], "modalities": []},
    {"configured": False, "destinations": ["s3"], "modalities": []},
    {"configured": True, "destinations": ["s3", "s3"], "modalities": ["text"]},
    {"configured": True, "destinations": ["unknown"], "modalities": ["text"]},
    {"configured": True, "destinations": ["s3"], "modalities": ["unknown"]},
])
def test_snapshot_rejects_invalid_logging_facts(fact):
    result, _ = collect(AgentClient([{"agentSummaries": []}]), BedrockClient({}))
    raw = snapshot_for(result).to_dict()
    raw["services"]["bedrock"]["resources"][0]["data"] = {
        "model_invocation_logging_configuration": fact,
    }
    with pytest.raises(Exception):
        snapshot_from_dict(raw)


def test_registry_counts_opt_in_order_and_metadata():
    assert len(SERVICE_SPECS) == 11
    assert len(DEFAULT_SERVICES) == 7
    assert len(check_specs()) == 42
    assert len(CORRELATION_RULES) == 5
    assert SERVICE_SPECS[-1].identifier == "bedrock"
    assert service_spec("bedrock").default_enabled is False
    assert service_spec("bedrock").completed_operations == ("ListAgents",)
    assert [check.identifier for check in service_spec("bedrock").checks] == [
        "AWSH-BEDROCK-001", "AWSH-BEDROCK-002",
    ]
    assert [check.severity for check in service_spec("bedrock").checks] == [
        Severity.MEDIUM, Severity.LOW,
    ]
    assert "bedrock" not in parse_services(None)
    assert parse_services("iam,bedrock") == ["iam", "bedrock"]
