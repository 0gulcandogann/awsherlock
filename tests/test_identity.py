"""Identity governance uses synthetic metadata and mocked AWS responses only."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.aws.context import ScanContext
from awsherlock.cli import app
from awsherlock.collectors.iam import collect_iam
from awsherlock.collectors.identity_events import normalize_activity, collect_identity_activity
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.identity_config import IdentityOptions, validate_inventory
from awsherlock.identity_facts import trust_fact
from awsherlock.reporting import render_html
from awsherlock.snapshot import capture_snapshot, read_snapshot, write_snapshot, SnapshotError
from test_s3 import aws_error

NOW = datetime(2026, 9, 17, tzinfo=timezone.utc)
ACCOUNT = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/worker"
USER = f"arn:aws:iam::{ACCOUNT}:user/integration"
POLICY = {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example/object"}}
TRUST = {"Statement": {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "lambda.amazonaws.com"}}}


def declaration(arn, kind="workload", principals=None, shared=False):
    return {"arn": arn, "kind": kind, "owner": "platform", "purpose": "workload", "allowed_principals": principals or [], "shared": shared}


def inventory(entries=None, complete=True):
    return {"schema_version": 1, "accounts": [ACCOUNT], "complete": complete,
            "identities": entries if entries is not None else [declaration(ROLE, principals=["lambda.amazonaws.com"]), declaration(USER)]}


@pytest.fixture
def identity_context():
    role = {"RoleName": "worker", "Arn": ROLE, "Path": "/", "CreateDate": NOW - timedelta(days=200),
            "RoleLastUsed": {"LastUsedDate": NOW - timedelta(days=2)}, "AssumeRolePolicyDocument": TRUST,
            "AttachedManagedPolicies": [], "RolePolicyList": [{"PolicyDocument": POLICY}],
            "Tags": [{"Key": "Owner", "Value": "platform"}, {"Key": "Purpose", "Value": "work"}]}
    user = {"UserName": "integration", "Arn": USER, "GroupList": [], "AttachedManagedPolicies": [],
            "UserPolicyList": [{"PolicyDocument": POLICY}], "Tags": role["Tags"]}
    iam = Mock()
    pages = {"get_account_authorization_details": [{"RoleDetailList": [role], "UserDetailList": [user]}],
             "list_access_keys": [{"AccessKeyMetadata": []}], "list_role_tags": [{"Tags": role["Tags"]}],
             "list_user_tags": [{"Tags": user["Tags"]}]}
    iam.get_paginator.side_effect = lambda operation: Mock(paginate=Mock(return_value=pages[operation]))
    iam.get_login_profile.side_effect = aws_error("NoSuchEntity")
    clients = {"iam": iam}
    for service, operation, key in [("lambda", "list_functions", "Functions"), ("ec2", "describe_instances", "Reservations"),
                                    ("bedrock-agent", "list_agents", "agentSummaries"),
                                    ("bedrock-agentcore-control", "list_agent_runtimes", "agentRuntimes"),
                                    ("accessanalyzer", "list_analyzers", "analyzers")]:
        client = Mock()
        client.get_paginator.return_value.paginate.return_value = [{key: []}]
        clients[service] = client
    clients["cloudtrail"] = Mock(lookup_events=Mock(return_value={"Events": []}))
    session = Mock()
    session.client.side_effect = lambda service, **kwargs: clients[service]
    context = ScanContext(ACCOUNT, f"arn:aws:iam::{ACCOUNT}:role/Auditor", "aws", None, "us-east-1", session,
                          identity_options=IdentityOptions(inventory=inventory()))
    return context, clients, role, user, pages


def snapshot_at(context):
    from awsherlock.collectors.common import CollectionResult
    from awsherlock.models import ScanMetadata
    from awsherlock.snapshot import Snapshot
    result = collect_iam(context, now=NOW)
    return Snapshot(ScanMetadata(scan_id="identity", started_at=NOW, account_id=context.account_id,
                                 region=context.region, version="test"), {"iam": CollectionResult(result.resources, result.issues)})


def test_secure_identity_governance_and_offline_replay(identity_context, tmp_path):
    context, clients, role, user, pages = identity_context
    snapshot = snapshot_at(context)
    report = evaluate_snapshot(snapshot)
    assert not report.incomplete and not report.findings
    assert len(report.identities) == 2
    assert report.identities[0]["ai_attribution"] == "declared_workload"
    path = tmp_path / "identity.json"
    write_snapshot(snapshot, path)
    assert evaluate_snapshot(read_snapshot(path)).to_dict() == report.to_dict()
    assert "Identity governance" in render_html(report)


@pytest.mark.parametrize("change,identifier", [
    ("owner", "AWSH-IAM-007"), ("purpose", "AWSH-IAM-008"), ("stale", "AWSH-IAM-009"),
    ("broad", "AWSH-IAM-010"), ("unregistered", "AWSH-IAM-011"), ("trust", "AWSH-IAM-012"),
])
def test_each_new_rule_insecure_then_secure(identity_context, change, identifier):
    context, clients, role, user, pages = identity_context
    assert not any(f.id == identifier for f in evaluate_snapshot(snapshot_at(context)).findings)
    registry = inventory()
    if change in {"owner", "purpose"}:
        role["Tags"] = [tag for tag in role["Tags"] if tag["Key"].lower() != change]
        registry["identities"][0][change] = ""
    elif change == "stale":
        role["RoleLastUsed"] = {"LastUsedDate": NOW - timedelta(days=91)}
    elif change == "broad":
        role["AssumeRolePolicyDocument"] = {"Statement": {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": "*"}}
    elif change == "unregistered":
        registry["identities"] = [declaration(USER)]
    else:
        registry["identities"][0]["allowed_principals"] = ["ec2.amazonaws.com"]
    context = replace(context, identity_options=replace(context.identity_options, inventory=registry))
    report = evaluate_snapshot(snapshot_at(context))
    assert any(f.id == identifier and f.resource_arn == ROLE for f in report.findings)


@pytest.mark.parametrize("last,created,status,finding", [
    (None, 200, "no_record", True), (None, 20, "no_record", False),
    (None, 200, "unknown", False), (90, 200, "recorded", False), (91, 200, "recorded", True),
])
def test_usage_window_never_used_and_missing_are_distinct(identity_context, last, created, status, finding):
    context, clients, role, user, pages = identity_context
    role["CreateDate"] = NOW - timedelta(days=created)
    role["RoleLastUsed"] = {} if status == "no_record" else ({"LastUsedDate": NOW - timedelta(days=last)} if last is not None else None)
    report = evaluate_snapshot(snapshot_at(context))
    assert any(f.id == "AWSH-IAM-009" for f in report.findings) == finding
    assert report.incomplete == (status == "unknown")


@pytest.mark.parametrize("registry", [None, inventory([], complete=False),
                                      {**inventory(), "accounts": ["999999999999"], "identities": []}])
def test_missing_partial_out_of_scope_registry_never_means_unapproved(identity_context, registry):
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, inventory=registry))
    report = evaluate_snapshot(snapshot_at(context))
    assert report.incomplete and not any(f.id in {"AWSH-IAM-011", "AWSH-IAM-012"} for f in report.findings)
    assert all(i["approval_status"] == "unknown" for i in report.identities)


def test_user_group_and_managed_policy_association(identity_context):
    context, clients, role, user, pages = identity_context
    arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    user["GroupList"] = ["automation"]
    pages["get_account_authorization_details"].append({"GroupDetailList": [
        {"GroupName": "automation", "Arn": f"arn:aws:iam::{ACCOUNT}:group/automation",
         "AttachedManagedPolicies": [{"PolicyArn": arn}], "GroupPolicyList": []}]})
    clients["iam"].get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    clients["iam"].get_policy_version.return_value = {"PolicyVersion": {"Document": {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}}}
    report = evaluate_snapshot(snapshot_at(context))
    assert {f.id for f in report.findings if f.resource_arn == USER} >= {"AWSH-IAM-001", "AWSH-IAM-002", "AWSH-IAM-003"}
    assert not report.incomplete
    clients["iam"].get_policy_version.assert_called_once_with(PolicyArn=arn, VersionId="v1")


def test_policy_denial_is_partial_and_keeps_known_grants(identity_context):
    context, clients, role, user, pages = identity_context
    role["AttachedManagedPolicies"] = [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
    clients["iam"].get_policy.side_effect = aws_error("AccessDenied")
    report = evaluate_snapshot(snapshot_at(context))
    assert report.incomplete and any(f.id == "AWSH-IAM-001" for f in report.findings)
    assert "secret-marker" not in json.dumps(report.to_dict())


def test_profile_tag_denial_does_not_become_owner_pass(identity_context):
    context, clients, role, user, pages = identity_context
    del role["Tags"]
    clients["iam"].get_paginator.side_effect = lambda operation: (
        Mock(paginate=Mock(side_effect=aws_error("AccessDenied"))) if operation == "list_role_tags"
        else Mock(paginate=Mock(return_value=pages[operation])))
    report = evaluate_snapshot(snapshot_at(context))
    assert report.incomplete
    assert "identity_profile" in next(i for i in report.identities if i["arn"] == ROLE)["missing_facts"]


def test_ai_name_and_sdk_policy_do_not_classify_ai(identity_context):
    context, clients, role, user, pages = identity_context
    role["RoleName"] = "ai-agent-worker"
    role["RolePolicyList"] = [{"PolicyDocument": {"Statement": {"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": "*"}}}]
    context = replace(context, identity_options=replace(context.identity_options, inventory=None))
    assert evaluate_snapshot(snapshot_at(context)).identities[0]["ai_attribution"] == "unknown"


@pytest.mark.parametrize("principal,condition,status,broad", [
    ("*", {}, "supported", True),
    ("*", {"ArnEquals": {"aws:PrincipalArn": USER}}, "supported", False),
    ("*", {"StringEquals": {"aws:PrincipalAccount": ACCOUNT}}, "supported", False),
    ("*", {"StringEquals": {"aws:PrincipalTag/team": "x"}}, "unknown", False),
    ({"AWS": USER}, {"StringEquals": {"sts:ExternalId": "external-secret-marker"}}, "supported", False),
])
def test_trust_supported_narrowed_and_unknown(principal, condition, status, broad):
    fact = trust_fact({"Statement": {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": principal, "Condition": condition}})
    assert fact["status"] == status and fact["broad"] == broad
    assert "external-secret-marker" not in str(fact)


@pytest.mark.parametrize("scoped", [True, False])
def test_oidc_audience_subject_scoping(scoped):
    conditions = {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                                    "token.actions.githubusercontent.com:sub": "repo:owner/repo:ref:refs/heads/main"}} if scoped else {}
    fact = trust_fact({"Statement": {"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
                                    "Principal": {"Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"}, "Condition": conditions}})
    assert fact["mechanisms"] == ["oidc"] and fact["broad"] == (not scoped)


def assume_event(caller, target=ROLE, key="memory-key-marker", mechanism="AssumeRole", source_key=None):
    identity = {"type": "IAMUser", "arn": caller, "accountId": caller.split(":")[4]}
    if source_key:
        identity = {"type": "AssumedRole", "accessKeyId": source_key,
                    "sessionContext": {"sessionIssuer": {"arn": caller}}}
    return {"eventSource": "sts.amazonaws.com", "eventName": mechanism, "eventTime": "2026-09-17T00:00:00Z",
            "userIdentity": identity, "requestParameters": {"roleArn": target, "externalId": "external-secret-marker"},
            "responseElements": {"credentials": {"accessKeyId": key, "sessionToken": "session-secret-marker"}}}


def role_event(role=ROLE, key="memory-key-marker"):
    return {"eventName": "ListBuckets", "eventTime": "2026-09-17T00:01:00Z",
            "userIdentity": {"type": "AssumedRole", "accessKeyId": key,
                             "sessionContext": {"sessionIssuer": {"arn": role}, "sourceIdentity": "source-secret-marker"}}}


@pytest.mark.parametrize("caller", [USER, "arn:aws:iam::999999999999:role/external"])
def test_same_and_cross_account_role_attribution_without_secret_export(caller):
    result = normalize_activity([assume_event(caller), role_event()], "us-east-1")
    observed = result[ROLE][-1]
    assert observed["caller_arn"] == caller and observed["attribution"] == "caller_observed"
    assert observed["chain"] == [caller]
    assert "marker" not in json.dumps(result)


def test_role_chain_correlates_only_observed_edges():
    other = f"arn:aws:iam::{ACCOUNT}:role/other"
    events = [assume_event(USER, target=other, key="first-key"),
              assume_event(other, source_key="first-key"), role_event()]
    observed = normalize_activity(events, "us-east-1")[ROLE][-1]
    assert observed["chain"] == [other, USER]
    assert observed["caller_arn"] == USER


def test_missing_assumption_event_is_issuer_only_not_ai():
    observed = normalize_activity([role_event()], "us-east-1")[ROLE][0]
    assert observed["attribution"] == "issuer_only" and observed["caller_arn"] is None


def test_oidc_observation_does_not_prove_ai():
    events = [assume_event(USER, mechanism="AssumeRoleWithWebIdentity"), role_event()]
    assert normalize_activity(events, "us-east-1")[ROLE][-1]["mechanism"] == "oidc"


def test_bounded_history_pagination_failure_preserves_valid_events(identity_context):
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, events=True))
    clients["cloudtrail"].lookup_events.side_effect = [
        {"Events": [{"CloudTrailEvent": json.dumps(assume_event(USER))}, {"CloudTrailEvent": json.dumps(role_event())}], "NextToken": "next"},
        aws_error("AccessDenied")]
    report = evaluate_snapshot(snapshot_at(context))
    assert report.incomplete
    activity = next(i for i in report.identities if i["arn"] == ROLE)["evidence"]["identity_activity"]
    assert not activity["complete"] and activity["events"][-1]["caller_arn"] == USER
    assert "marker" not in json.dumps(report.to_dict())


def test_event_page_budget_reports_truncation(identity_context):
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, events=True, max_pages=1))
    clients["cloudtrail"].lookup_events.return_value = {"Events": [], "NextToken": "next"}
    report = evaluate_snapshot(snapshot_at(context))
    assert report.incomplete and clients["cloudtrail"].lookup_events.call_count == 1
    assert not report.identities[0]["evidence"]["identity_activity"]["complete"]


def test_no_history_is_not_proof_of_non_use(identity_context):
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, events=True))
    report = evaluate_snapshot(snapshot_at(context))
    assert report.identities[0]["observed_mechanisms"] == []
    assert report.identities[0]["ai_attribution"] == "declared_workload"


def test_native_ai_and_regular_workload_bindings(identity_context):
    context, clients, role, user, pages = identity_context
    clients["lambda"].get_paginator.return_value.paginate.return_value = [{"Functions": [{"FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:worker", "Role": ROLE}]}]
    report = evaluate_snapshot(snapshot_at(context))
    assert report.identities[0]["ai_attribution"] == "declared_workload"
    assert next(i for i in report.identities if i["arn"] == ROLE)["evidence"]["identity_bindings"][0]["service"] == "lambda"
    context = replace(context, identity_options=replace(context.identity_options, ai_services=True))
    clients["bedrock-agent"].get_paginator.return_value.paginate.return_value = [{"agentSummaries": [{"agentId": "ABCDEFGHIJ"}]}]
    clients["bedrock-agent"].get_agent.return_value = {"agent": {"agentArn": f"arn:aws:bedrock:us-east-1:{ACCOUNT}:agent/ABCDEFGHIJ", "agentResourceRoleArn": ROLE, "instruction": "prompt-secret-marker"}}
    runtime_id = "RuntimeName-abcdefghij"
    runtime_arn = f"arn:aws:bedrock-agentcore:us-east-1:{ACCOUNT}:runtime/{runtime_id}"
    clients["bedrock-agentcore-control"].get_paginator.return_value.paginate.return_value = [{"agentRuntimes": [{
        "agentRuntimeId": runtime_id, "agentRuntimeArn": runtime_arn, "agentRuntimeVersion": "2",
    }]}]
    clients["bedrock-agentcore-control"].get_agent_runtime.return_value = {
        "agentRuntimeId": runtime_id, "agentRuntimeArn": runtime_arn, "agentRuntimeVersion": "2",
        "roleArn": ROLE, "environmentVariables": {"TOKEN": "env-secret-marker"},
    }
    report = evaluate_snapshot(snapshot_at(context))
    identity = next(i for i in report.identities if i["arn"] == ROLE)
    assert identity["ai_attribution"] == "verified_ai_binding"
    assert {b["service"] for b in identity["evidence"]["identity_bindings"]} == {"lambda", "bedrock", "agentcore"}
    assert next(b for b in identity["evidence"]["identity_bindings"]
                if b["service"] == "agentcore")["resource_version"] == "2"
    clients["bedrock-agentcore-control"].get_agent_runtime.assert_called_once_with(
        agentRuntimeId=runtime_id, agentRuntimeVersion="2",
    )
    assert "marker" not in json.dumps(report.to_dict())


def test_shared_declared_ai_does_not_attribute_each_call(identity_context):
    context, clients, role, user, pages = identity_context
    registry = inventory([declaration(ROLE, "ai", ["lambda.amazonaws.com"], shared=True), declaration(USER, "human")])
    context = replace(context, identity_options=replace(context.identity_options, inventory=registry))
    report = evaluate_snapshot(snapshot_at(context))
    ai = next(i for i in report.identities if i["arn"] == ROLE)
    human = next(i for i in report.identities if i["arn"] == USER)
    assert ai["ai_attribution"] == "declared_ai" and ai["shared_declared"]
    assert ai["observed_mechanisms"] == []
    assert human["ai_attribution"] == "declared_human"


def test_no_analyzer_is_visible_not_secure(identity_context):
    context, clients, role, user, pages = identity_context
    context = replace(context, identity_options=replace(context.identity_options, analyzers=True))
    report = evaluate_snapshot(snapshot_at(context))
    assert report.incomplete
    assert any(i["operation"] == "IdentityAnalyzers" for i in report.coverage[0]["issues"])


@pytest.mark.parametrize("fact,value", [("identity_profile", {"owner": "true"}),
                                       ("identity_activity", {"days": 900}), ("identity_requested", False)])
def test_malformed_offline_identity_facts_rejected(identity_context, fact, value):
    snapshot = snapshot_at(identity_context[0])
    snapshot.services["iam"].resources[0].data[fact] = value
    with pytest.raises(SnapshotError):
        snapshot.to_dict()


def test_offline_governance_and_inventory_without_aws(identity_context, tmp_path, monkeypatch):
    snapshot = snapshot_at(identity_context[0])
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    registry = tmp_path / "inventory.json"
    registry.write_text(json.dumps(inventory([declaration(ROLE, "ai", ["lambda.amazonaws.com"]), declaration(USER, "ai")])))
    factory = Mock(side_effect=AssertionError("Offline"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    result = CliRunner().invoke(app, ["scan", str(path), "--identity-governance", "--identity-inventory", str(registry), "--output", "json"])
    assert result.exit_code == 0, result.output
    assert all(i["ai_attribution"] == "declared_ai" for i in json.loads(result.stdout)["identities"])
    factory.assert_not_called()


@pytest.mark.parametrize("args", [["--identity-events"], ["--identity-inventory", "missing.json"],
                                  ["--identity-governance", "--identity-days", "91"],
                                  ["--identity-governance", "--services", "s3"],
                                  ["facts.json", "--identity-governance", "--identity-events"]])
def test_invalid_identity_options_fail_before_auth(monkeypatch, args):
    factory = Mock()
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    assert CliRunner().invoke(app, ["scan", *args]).exit_code == 2
    factory.assert_not_called()


def test_old_snapshot_explicit_governance_missing_facts_visible(identity_context):
    context = replace(identity_context[0], identity_options=None)
    snapshot = snapshot_at(context)
    before = evaluate_snapshot(snapshot)
    report = evaluate_snapshot(snapshot, identity_governance=True)
    assert not before.incomplete and report.incomplete
    assert all(i["ai_attribution"] == "unknown" for i in report.identities)


@pytest.mark.parametrize("change", ["extra", "scope", "duplicate", "wildcard", "secret"])
def test_inventory_schema_is_exact(change):
    data = inventory()
    if change == "extra": data["extra"] = True
    elif change == "scope": data["accounts"] = ["999999999999"]
    elif change == "duplicate": data["identities"].append(data["identities"][0])
    elif change == "wildcard": data["identities"][0]["allowed_principals"] = ["*"]
    else: data["identities"][0]["sessionToken"] = "secret"
    with pytest.raises(ValueError):
        validate_inventory(data)
