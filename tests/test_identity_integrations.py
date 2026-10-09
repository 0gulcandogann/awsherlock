"""SDK request contracts and bounded failure paths for optional identity reads."""

from dataclasses import replace
import json

import boto3
import pytest
from botocore.stub import Stubber

from awsherlock.collectors.identity_events import normalize_activity
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.identity_config import IdentityOptions
from awsherlock.organization import scan_organization
from awsherlock.regional import scan_regions
from test_identity import (identity_context, snapshot_at, declaration, inventory, assume_event, role_event,
                           NOW, ACCOUNT, ROLE, USER)
from test_s3 import aws_error


def sdk(service):
    return boto3.client(service, region_name="us-east-1", aws_access_key_id="synthetic", aws_secret_access_key="synthetic")


def role_identity(report):
    return next(i for i in report.identities if i["arn"] == ROLE)


def test_bedrock_and_agentcore_real_sdk_request_contracts(identity_context):
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, ai_services=True))
    bedrock, core = sdk("bedrock-agent"), sdk("bedrock-agentcore-control")
    clients["bedrock-agent"], clients["bedrock-agentcore-control"] = bedrock, core
    agent_arn = f"arn:aws:bedrock:us-east-1:{ACCOUNT}:agent/ABCDEFGHIJ"
    runtime_id = "RuntimeName-abcdefghij"
    runtime_arn = f"arn:aws:bedrock-agentcore:us-east-1:{ACCOUNT}:runtime/{runtime_id}"
    with Stubber(bedrock) as b, Stubber(core) as c:
        b.add_response("list_agents", {"agentSummaries": [{"agentId": "ABCDEFGHIJ", "agentName": "agent", "agentStatus": "PREPARED", "updatedAt": NOW}]}, {})
        b.add_response("get_agent", {"agent": {"agentId": "ABCDEFGHIJ", "agentName": "agent", "agentArn": agent_arn,
                       "agentVersion": "DRAFT", "agentStatus": "PREPARED", "idleSessionTTLInSeconds": 60,
                       "agentResourceRoleArn": ROLE, "createdAt": NOW, "updatedAt": NOW, "instruction": "prompt-secret-marker" * 3}}, {"agentId": "ABCDEFGHIJ"})
        c.add_response("list_agent_runtimes", {"agentRuntimes": [{"agentRuntimeArn": runtime_arn,
                       "agentRuntimeId": runtime_id, "agentRuntimeVersion": "1", "agentRuntimeName": "runtime",
                       "description": "ignored", "lastUpdatedAt": NOW, "status": "READY"}]}, {})
        c.add_response("get_agent_runtime", {"agentRuntimeArn": runtime_arn, "agentRuntimeName": "runtime",
                       "agentRuntimeId": runtime_id, "agentRuntimeVersion": "1", "createdAt": NOW,
                       "lastUpdatedAt": NOW, "roleArn": ROLE, "status": "READY", "lifecycleConfiguration": {},
                       "environmentVariables": {"SECRET": "environment-secret-marker"}},
                       {"agentRuntimeId": runtime_id, "agentRuntimeVersion": "1"})
        report = evaluate_snapshot(snapshot_at(context))
        assert not report.incomplete
        assert role_identity(report)["ai_attribution"] == "verified_ai_binding"
        assert "marker" not in json.dumps(report.to_dict())
        b.assert_no_pending_responses()
        c.assert_no_pending_responses()


def test_existing_unused_access_analyzer_real_sdk_detail_pagination(identity_context):
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, analyzers=True))
    client = sdk("accessanalyzer")
    clients["accessanalyzer"] = client
    arn = f"arn:aws:access-analyzer:us-east-1:{ACCOUNT}:analyzer/existing"
    summary = {"id": "finding-1", "analyzedAt": NOW, "createdAt": NOW, "updatedAt": NOW,
               "resourceType": "AWS::IAM::Role", "resourceOwnerAccount": ACCOUNT, "status": "ACTIVE",
               "resource": ROLE, "findingType": "UnusedPermission"}
    with Stubber(client) as stub:
        stub.add_response("list_analyzers", {"analyzers": [{"arn": arn, "name": "existing", "type": "ACCOUNT_UNUSED_ACCESS",
                          "createdAt": NOW, "status": "ACTIVE", "configuration": {"unusedAccess": {"unusedAccessAge": 90}}}]}, {})
        stub.add_response("list_findings_v2", {"findings": [summary]}, {"analyzerArn": arn})
        stub.add_response("get_finding_v2", {**summary, "findingDetails": [{"unusedPermissionDetails": {
                          "serviceNamespace": "s3", "actions": [{"action": "DeleteObject"}]}}], "nextToken": "next"},
                          {"analyzerArn": arn, "id": "finding-1"})
        stub.add_response("get_finding_v2", {**summary, "findingDetails": [{"unusedPermissionDetails": {"serviceNamespace": "ec2"}}]},
                          {"analyzerArn": arn, "id": "finding-1", "nextToken": "next"})
        report = evaluate_snapshot(snapshot_at(context))
        assert not report.incomplete
        finding = role_identity(report)["evidence"]["identity_analyzer_findings"][0]
        assert finding["unused_actions"] == ["s3:DeleteObject"]
        assert finding["unused_services"] == ["ec2", "s3"]
        assert finding["tracking_window_days"] == 90
        stub.assert_no_pending_responses()


def test_ec2_instance_profile_binding_contract_and_cache(identity_context):
    context, clients, role, user, pages = identity_context
    profile = f"arn:aws:iam::{ACCOUNT}:instance-profile/worker"
    clients["ec2"].get_paginator.return_value.paginate.return_value = [{"Reservations": [{"Instances": [
        {"InstanceId": "i-first", "IamInstanceProfile": {"Arn": profile}},
        {"InstanceId": "i-second", "IamInstanceProfile": {"Arn": profile}}]}]}]
    clients["iam"].get_instance_profile.return_value = {"InstanceProfile": {"Arn": profile, "Roles": [{"Arn": ROLE}]}}
    report = evaluate_snapshot(snapshot_at(context))
    assert len(role_identity(report)["evidence"]["identity_bindings"]) == 2
    clients["iam"].get_instance_profile.assert_called_once_with(InstanceProfileName="worker")
    assert role_identity(report)["ai_attribution"] == "declared_workload"


def test_native_denial_preserves_ordinary_binding_and_not_ai(identity_context):
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, ai_services=True))
    clients["lambda"].get_paginator.return_value.paginate.return_value = [{"Functions": [{"FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:worker", "Role": ROLE}]}]
    clients["bedrock-agent"].get_paginator.return_value.paginate.side_effect = aws_error("AccessDenied")
    report = evaluate_snapshot(snapshot_at(context))
    assert report.incomplete
    assert role_identity(report)["ai_attribution"] == "declared_workload"
    assert role_identity(report)["evidence"]["identity_bindings"][0]["service"] == "lambda"


def test_native_binding_wrong_account_never_marks_ai(identity_context):
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, ai_services=True))
    clients["bedrock-agent"].get_paginator.return_value.paginate.return_value = [{"agentSummaries": [{"agentId": "ABCDEFGHIJ"}]}]
    clients["bedrock-agent"].get_agent.return_value = {"agent": {"agentArn": f"arn:aws:bedrock:us-east-1:{ACCOUNT}:agent/ABCDEFGHIJ", "agentResourceRoleArn": ROLE.replace(ACCOUNT, "999999999999")}}
    report = evaluate_snapshot(snapshot_at(context))
    assert report.incomplete and role_identity(report)["ai_attribution"] != "verified_ai_binding"


def test_workload_later_page_failure_preserves_bindings(identity_context):
    context, clients, role, user, pages = identity_context
    def functions():
        yield {"Functions": [{"FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:worker", "Role": ROLE}], "NextMarker": "next"}
        raise aws_error("AccessDenied")
    clients["lambda"].get_paginator.return_value.paginate.return_value = functions()
    report = evaluate_snapshot(snapshot_at(context))
    assert report.incomplete
    assert len(role_identity(report)["evidence"]["identity_bindings"]) == 1


def test_source_identity_presence_never_classifies_ai(identity_context):
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, inventory=None, events=True))
    clients["cloudtrail"].lookup_events.return_value = {"Events": [{"CloudTrailEvent": json.dumps(role_event())}]}
    identity = role_identity(evaluate_snapshot(snapshot_at(context)))
    assert identity["ai_attribution"] == "unknown"
    assert identity["evidence"]["identity_activity"]["events"][0]["source_identity_present"]
    assert "source-secret-marker" not in json.dumps(identity)


def test_ambiguous_reused_session_name_is_not_caller_attribution():
    first, second = assume_event(USER), assume_event("arn:aws:iam::999999999999:user/other")
    for event in (first, second):
        event["responseElements"] = {"assumedRoleUser": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/worker/reused"}}
    activity = role_event(key="unmatched")
    activity["userIdentity"]["arn"] = f"arn:aws:sts::{ACCOUNT}:assumed-role/worker/reused"
    record = normalize_activity([first, second, activity], "us-east-1")[ROLE][-1]
    assert record["attribution"] == "issuer_only" and record["caller_arn"] is None


def test_role_chain_missing_origin_is_explicit():
    caller = f"arn:aws:iam::{ACCOUNT}:role/upstream"
    record = normalize_activity([assume_event(caller, source_key="unknown"), role_event()], "us-east-1")[ROLE][-1]
    assert record["caller_arn"] == caller and not record["chain_complete"]


def test_failed_assumption_is_not_a_session_edge():
    denied = {**assume_event(USER), "errorCode": "AccessDenied"}
    record = normalize_activity([denied, role_event()], "us-east-1")[ROLE][-1]
    assert record["attribution"] == "issuer_only"


def test_event_region_and_fresh_scan_isolation(identity_context):
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, events=True, regions=("us-east-1", "eu-west-1")))
    clients["cloudtrail"].lookup_events.side_effect = [{"Events": [{"CloudTrailEvent": json.dumps(role_event())}]}, {"Events": []}]
    identity = role_identity(evaluate_snapshot(snapshot_at(context)))
    assert [e["region"] for e in identity["evidence"]["identity_activity"]["events"]] == ["us-east-1"]
    clients["cloudtrail"].lookup_events.side_effect = None
    clients["cloudtrail"].lookup_events.return_value = {"Events": []}
    assert role_identity(evaluate_snapshot(snapshot_at(context)))["observed_mechanisms"] == []


def test_malformed_event_is_partial_and_not_raw_export(identity_context):
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, events=True))
    clients["cloudtrail"].lookup_events.return_value = {"Events": [{"CloudTrailEvent": "{secret-marker"}]}
    report = evaluate_snapshot(snapshot_at(context))
    assert report.incomplete and "secret-marker" not in json.dumps(report.to_dict())


def test_multiregion_report_keeps_single_global_identity_inventory(identity_context):
    context, clients, role, user, pages = identity_context
    report = scan_regions(context, ["iam"], ["us-east-1", "eu-west-1"])
    assert len(report.identities) == 2
    assert len(report.coverage) == 1


def test_tag_declaration_is_separate_from_verified_binding(identity_context):
    context, clients, role, user, pages = identity_context
    role["Tags"].append({"Key": "IdentityType", "Value": "ai"})
    context = replace(context, identity_options=replace(context.identity_options, inventory=None))
    identity = role_identity(evaluate_snapshot(snapshot_at(context)))
    assert identity["ai_attribution"] == "declared_ai" and identity["classification_source"] == "IdentityType tag"


def test_service_linked_roles_do_not_get_owner_purpose_stale_findings(identity_context):
    context, clients, role, user, pages = identity_context
    role["Path"] = "/aws-service-role/example.amazonaws.com/"
    role["Tags"] = []
    role["RoleLastUsed"] = {}
    registry = inventory()
    registry["identities"][0]["owner"] = registry["identities"][0]["purpose"] = ""
    context = replace(context, identity_options=replace(context.identity_options, inventory=registry))
    report = evaluate_snapshot(snapshot_at(context))
    assert not any(f.resource_arn == ROLE and f.id in {"AWSH-IAM-007", "AWSH-IAM-008", "AWSH-IAM-009"} for f in report.findings)


def test_fake_oidc_condition_prefix_never_proves_scoped_trust():
    from awsherlock.identity_facts import trust_fact
    fact = trust_fact({"Statement": {"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
                      "Principal": {"Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/real.example"},
                      "Condition": {"StringEquals": {"fake.example:aud": "sts.amazonaws.com", "fake.example:sub": "workload"}}}})
    assert fact["status"] == "unknown"


def test_observed_unapproved_caller_is_reviewed(identity_context):
    context, clients, role, user, pages = identity_context
    role["AssumeRolePolicyDocument"] = {"Statement": {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": USER}}}
    registry = inventory([declaration(ROLE, "ai", [USER]), declaration(USER)])
    context = replace(context, identity_options=replace(context.identity_options, inventory=registry, events=True))
    caller = "arn:aws:iam::999999999999:user/external"
    clients["cloudtrail"].lookup_events.return_value = {"Events": [{"CloudTrailEvent": json.dumps(assume_event(caller))}, {"CloudTrailEvent": json.dumps(role_event())}]}
    report = evaluate_snapshot(snapshot_at(context))
    assert any(f.id == "AWSH-IAM-012" and f.resource_arn == ROLE for f in report.findings)


def test_iam_user_direct_activity_is_not_automatically_ai():
    event = {"eventName": "ListBuckets", "eventTime": "2026-09-17T00:00:00Z",
             "userIdentity": {"type": "IAMUser", "arn": USER, "accountId": ACCOUNT, "accessKeyId": "key-secret-marker"}}
    record = normalize_activity([event], "us-east-1")[USER][0]
    assert record["mechanism"] == "iam_user" and record["caller_arn"] == USER
    assert "marker" not in json.dumps(record)


def test_temporary_federated_user_maps_to_issuer_without_ai_assumption():
    event = {"eventName": "ListBuckets", "eventTime": "2026-09-17T00:00:00Z", "userIdentity": {
        "type": "FederatedUser", "arn": f"arn:aws:sts::{ACCOUNT}:federated-user/session",
        "sessionContext": {"sessionIssuer": {"arn": USER}}}}
    record = normalize_activity([event], "us-east-1")[USER][0]
    assert record["mechanism"] == "federation" and record["attribution"] == "issuer_only"


def test_unmapped_sso_actor_is_visible_unknown_coverage(identity_context):
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, events=True))
    clients["cloudtrail"].lookup_events.return_value = {"Events": [{"CloudTrailEvent": json.dumps({
        "eventName": "ListBuckets", "eventTime": "2026-09-17T00:00:00Z",
        "userIdentity": {"type": "IdentityCenterUser", "accountId": ACCOUNT, "credentialId": "credential-secret-marker"}})}]}
    report = evaluate_snapshot(snapshot_at(context))
    assert report.incomplete
    assert any("cannot be mapped" in issue["message"] for issue in report.coverage[0]["issues"])
    assert "marker" not in json.dumps(report.to_dict())


def test_external_id_control_must_cover_every_allow_branch(identity_context):
    context, clients, role, user, pages = identity_context
    registry = inventory()
    registry["identities"][0]["external_id_required"] = True
    registry["identities"][0]["allowed_principals"] = [USER]
    protected = {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": USER},
                 "Condition": {"StringEquals": {"sts:ExternalId": "secret-marker"}}}
    role["AssumeRolePolicyDocument"] = {"Statement": [protected, {k: v for k, v in protected.items() if k != "Condition"}]}
    context = replace(context, identity_options=replace(context.identity_options, inventory=registry))
    report = evaluate_snapshot(snapshot_at(context))
    assert any(f.id == "AWSH-IAM-012" and f.resource_arn == ROLE for f in report.findings)
    assert "secret-marker" not in json.dumps(report.to_dict())
    role["AssumeRolePolicyDocument"] = {"Statement": [protected]}
    assert not any(f.id == "AWSH-IAM-012" for f in evaluate_snapshot(snapshot_at(context)).findings)


def test_lookup_rate_budget_and_timeout_config_are_preserved(identity_context, monkeypatch):
    from botocore.config import Config
    from awsherlock.collectors import identity_events
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, events=True),
                      client_config=Config(connect_timeout=1, read_timeout=2, retries={"max_attempts": 1}))
    clock = [0.0]
    calls = []
    monkeypatch.setattr(identity_events.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(identity_events.time, "sleep", lambda delay: clock.__setitem__(0, clock[0] + delay))
    def lookup(**params):
        calls.append(clock[0])
        return {"Events": [], **({"NextToken": "next"} if len(calls) == 1 else {})}
    clients["cloudtrail"].lookup_events.side_effect = lookup
    report = evaluate_snapshot(snapshot_at(context))
    assert not report.incomplete
    assert calls[1] - calls[0] >= 0.5
    context.session.client.assert_any_call("cloudtrail", region_name="us-east-1", config=context.client_config)


def test_time_budget_stops_before_another_lookup(identity_context, monkeypatch):
    from awsherlock.collectors import identity_events
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, events=True, max_seconds=1))
    clock = [0.0]
    monkeypatch.setattr(identity_events.time, "monotonic", lambda: clock[0])
    def lookup(**params):
        clock[0] = 2.0
        return {"Events": [], "NextToken": "next"}
    clients["cloudtrail"].lookup_events.side_effect = lookup
    report = evaluate_snapshot(snapshot_at(context))
    assert report.incomplete and clients["cloudtrail"].lookup_events.call_count == 1


@pytest.mark.parametrize("regions", [None, ["us-east-1", "eu-west-1"]])
def test_organization_preserves_identity_config_and_account_isolation(identity_context, monkeypatch, regions):
    from unittest.mock import Mock
    from awsherlock.collectors.common import CollectionResult
    from awsherlock.identity_config import approval_fact
    context, clients, role, user, pages = identity_context
    organization = Mock()
    organization.get_paginator.return_value.paginate.return_value = [{"Accounts": [
        {"Id": "000000000001", "Name": "one", "State": "ACTIVE"},
        {"Id": "000000000002", "Name": "two", "State": "ACTIVE"}]}]
    clients["organizations"] = organization
    captured = []
    def capture(target, services, **kwargs):
        captured.append(target)
        original = snapshot_at(context)
        resources = []
        for resource in original.services["iam"].resources:
            arn = resource.resource_arn.replace(ACCOUNT, target.account_id)
            data = {**resource.data, "identity_approval": approval_fact(target.account_id, arn, target.identity_options.inventory)}
            resources.append(replace(resource, account_id=target.account_id, resource_arn=arn, data=data))
        return replace(original, metadata=replace(original.metadata, account_id=target.account_id),
                       services={"iam": CollectionResult(resources, [])})
    factory = Mock(side_effect=lambda **kwargs: replace(context, account_id=kwargs["role"].split(":")[4], identity_options=None))
    monkeypatch.setattr("awsherlock.organization.create_scan_context", factory)
    monkeypatch.setattr("awsherlock.organization.capture_snapshot", capture)
    monkeypatch.setattr("awsherlock.regional.capture_snapshot", capture)
    report = scan_organization(context, ["iam"], selected_accounts=["000000000001"], regions=regions)
    assert factory.call_count == 1 and len(report.identities) == 2
    assert all(target.identity_options == context.identity_options for target in captured)
    assert all(i["account_id"] == "000000000001" and i["approval_status"] == "unknown" for i in report.identities)
    assert not any(ACCOUNT in i["arn"] for i in report.identities)
