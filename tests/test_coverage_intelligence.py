"""Offline Coverage Intelligence stays evidence-derived and conservative."""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.collectors.common import CollectionIssue, CollectionResult
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.models import (
    Relationship,
    RelationshipEvidence,
    RelationshipType,
    Resource,
    ResourceRef,
    ScanMetadata,
)
from awsherlock.snapshot import Snapshot, write_snapshot


ACCOUNT = "123456789012"
REGION = "eu-central-1"
RUNTIME = "ExampleRuntime-abcdefghij"


def module():
    return importlib.import_module("awsherlock.coverage_intelligence")


def snapshot(*, service="s3", issues=(), resources=(), relationships=(), schema=2):
    return Snapshot(
        ScanMetadata(
            scan_id="coverage-scan",
            started_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
            account_id=ACCOUNT,
            region=REGION,
            version="0.5.0",
        ),
        {service: CollectionResult(list(resources), list(issues))},
        tuple(relationships),
        schema,
    )


def diagnostics(value):
    return module().build_coverage_diagnostics(value, evaluate_snapshot(value))


def relationship():
    return Relationship(
        source=ResourceRef(
            service="agentcore",
            resource_type="runtime-endpoint",
            account_id=ACCOUNT,
            region=REGION,
            resource_id=f"{RUNTIME}:production",
            resource_arn=(
                f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/{RUNTIME}"
                "/runtime-endpoint/production"
            ),
        ),
        relationship_type=RelationshipType.USES,
        target=ResourceRef(
            service="agentcore",
            resource_type="runtime-version",
            account_id=ACCOUNT,
            region=REGION,
            resource_id=f"{RUNTIME}:2",
        ),
        evidence=(RelationshipEvidence(
            service="agentcore", fact="live_version", operation="GetAgentRuntimeEndpoint"
        ),),
    )


def write(value, path):
    write_snapshot(value, path)
    return path


def limitations(document):
    return [item for row in document["services"] for item in row["limitations"]]


def test_contract_reports_recorded_evidence_without_security_pass_or_score():
    value = snapshot()
    document = diagnostics(value)
    assert document["kind"] == "coverage-diagnostics"
    assert document["schema_version"] == 1
    assert document["source_snapshot"] == {
        "scan_id": "coverage-scan",
        "started_at": "2026-01-02T03:04:05+00:00",
        "account_id": ACCOUNT,
        "region": REGION,
        "producer_version": "0.5.0",
        "snapshot_schema_version": 2,
        "supports_relationships": True,
    }
    assert document["services"][0]["coverage_status"] == "COMPLETE"
    assert document["services"][0]["uncertainty"][0]["reason_code"] == "COMPLETENESS_NOT_PROVEN"
    rendered = json.dumps(document).lower()
    assert '"coverage_percentage"' not in rendered and '"coverage_score"' not in rendered
    assert '"overall_status": "pass"' not in rendered


@pytest.mark.parametrize(("message", "reason"), [
    ("AccessDenied", "ACCESS_DENIED"),
    ("AWS request throttled", "THROTTLED"),
    ("Invalid AWS response", "INVALID_RESPONSE"),
    ("AWS request timed out", "REQUEST_TIMEOUT"),
    ("AWS endpoint connection failed", "ENDPOINT_CONNECTION_FAILED"),
    ("AWS credentials expired or invalid", "CREDENTIALS_INVALID"),
    ("Event history page/time budget exhausted", "BUDGET_EXHAUSTED"),
    ("arbitrary private failure detail", "CAUSE_NOT_ESTABLISHED"),
])
def test_known_sanitized_reasons_are_bounded_and_unknown_text_is_not_exported(message, reason):
    value = snapshot(issues=[CollectionIssue(None, "ListBuckets", message)])
    document = diagnostics(value)
    item = limitations(document)[0]
    assert item["reason_code"] == reason
    assert message not in json.dumps(document) or message in {
        "AccessDenied", "AWS request throttled", "Invalid AWS response",
        "AWS request timed out", "AWS endpoint connection failed",
        "AWS credentials expired or invalid", "Event history page/time budget exhausted",
    }
    assert "discarded-private-detail" not in json.dumps(document)


@pytest.mark.parametrize("message", [
    "AccessDenied: attacker-controlled text",
    "AccessDenied: SecretMarker123",
    "AccessDenied:",
    "AccessDeniedExtra",
    "AccessDenied!",
    "accessdenied",
    "ACCESSDENIED",
])
def test_access_denied_variants_do_not_establish_a_specific_cause(message):
    value = snapshot(issues=[CollectionIssue(None, "UnknownOperation", message)])
    document = diagnostics(value)
    item = limitations(document)[0]
    assert item["reason_code"] == "CAUSE_NOT_ESTABLISHED"
    assert item["operation"] is None
    assert message not in module().render_coverage_json(document)
    assert message not in module().render_coverage_console(document)
    assert "SecretMarker123" not in module().render_coverage_json(document)
    assert "SecretMarker123" not in module().render_coverage_console(document)


def test_unknown_operation_is_not_exported_as_validated_provenance():
    payload = "<svg onload=alert(1)>SecretMarker"
    value = snapshot(issues=[CollectionIssue("bucket", "GetSecretMarker", payload)])
    item = limitations(diagnostics(value))[0]
    assert item["operation"] is None
    assert item["reason_code"] == "CAUSE_NOT_ESTABLISHED"
    assert payload not in json.dumps(diagnostics(value))


@pytest.mark.parametrize(("service", "operation"), [
    ("s3", "GetAccountPublicAccessBlock"),
    ("s3", "GetBucketLocation"),
    ("s3", "CreateRegionalClient"),
    ("secretsmanager", "SecretMetadata"),
    ("rds", "RDSClient"),
])
def test_known_collector_operations_retain_validated_provenance(service, operation):
    value = snapshot(service=service, issues=[CollectionIssue(None, operation, "Invalid AWS response")])
    assert limitations(diagnostics(value))[0]["operation"] == operation


@pytest.mark.parametrize(("operation", "expected"), [
    ("RequiredFact", "EVALUATION_INCOMPLETE"),
    ("RequiredCollection", "COLLECTION_INCOMPLETE"),
    ("CheckSelection", "SCOPE_NOT_RECORDED"),
    ("ResourceSelection", "SCOPE_NOT_RECORDED"),
])
def test_evaluation_and_scope_limitations_use_recorded_operations(operation, expected):
    value = snapshot(issues=[CollectionIssue(None, operation, "private detail")])
    item = limitations(diagnostics(value))[0]
    assert item["reason_code"] == expected and item["operation"] == operation
    assert item["issue_reference"]["source_field"] == f"report.coverage.s3.issues"
    assert "private detail" not in json.dumps(diagnostics(value))


def test_unsupported_operation_claim_is_not_invented_from_ambiguous_issue():
    value = snapshot(issues=[CollectionIssue(None, "ListAgentRuntimeEndpoints", "Invalid AWS response")])
    item = limitations(diagnostics(value))[0]
    assert item["reason_code"] == "INVALID_RESPONSE"
    assert item["reason_code"] != "UNSUPPORTED_OPERATION"


def test_v1_and_v2_relationship_capabilities_are_truthful_and_positive_only():
    v1 = diagnostics(snapshot(schema=1))
    v2_empty = diagnostics(snapshot())
    v2_positive = diagnostics(snapshot(relationships=[relationship()]))
    assert v1["relationship_coverage"]["capability"] == "UNSUPPORTED"
    assert v1["relationship_coverage"]["reason_code"] == "RELATIONSHIPS_UNSUPPORTED"
    assert v2_empty["relationship_coverage"]["capability"] == "POSITIVE_ONLY"
    assert v2_empty["relationship_coverage"]["observed_relationships"] == 0
    assert v2_positive["relationship_coverage"]["observed_relationships"] == 1
    assert v2_empty["relationship_coverage"]["reason_code"] == "RELATIONSHIP_COMPLETENESS_NOT_PROVEN"
    assert "no relationships exist" not in json.dumps(v2_empty).lower()


def test_missing_findings_and_relationships_never_become_negative_conclusions():
    document = diagnostics(snapshot())
    assert document["summary"]["recorded_findings"] == 0
    assert document["summary"]["recorded_relationships"] == 0
    assert "NO_FINDINGS_IS_NOT_SECURITY_PASS" in document["unsupported_conclusions"]
    assert "MISSING_RELATIONSHIP_IS_NOT_PROOF_OF_ABSENCE" in document["unsupported_conclusions"]


def test_region_scope_and_iam_global_scope_are_not_borrowed():
    iam = diagnostics(snapshot(service="iam"))["services"][0]
    bucket = diagnostics(snapshot(service="s3"))["services"][0]
    regional = diagnostics(snapshot(service="ec2"))["services"][0]
    assert iam["region"] is None and iam["scope"] == "global"
    assert bucket["region"] is None and bucket["scope"] == "bucket"
    assert regional["region"] == REGION and regional["scope"] == "regional"


def test_default_and_opt_in_are_registry_metadata_not_collection_history():
    document = diagnostics(snapshot(service="bedrock"))
    recorded = document["services"][0]
    absent = {row["service"]: row for row in document["unrecorded_services"]}
    assert recorded["registered_mode"] == "OPT_IN" and recorded["recorded"] is True
    assert absent["s3"]["registered_mode"] == "DEFAULT"
    assert absent["s3"]["reason_code"] == "SCOPE_NOT_RECORDED"
    assert all("disabled" not in row["explanation"].lower() for row in document["unrecorded_services"])


def test_agentcore_denied_reads_remain_incomplete_without_no_endpoint_claim():
    value = snapshot(service="iam", issues=[
        CollectionIssue(None, "ListAgentRuntimeEndpoints", "AccessDenied"),
        CollectionIssue(None, "GetAgentRuntime", "AWS request throttled"),
    ])
    document = diagnostics(value)
    assert [item["reason_code"] for item in limitations(document)] == ["THROTTLED", "ACCESS_DENIED"]
    assert "no endpoint" not in json.dumps(document).lower()


def test_partial_agentcore_pagination_preserves_positive_route_and_limitation():
    value = snapshot(
        service="iam",
        issues=[CollectionIssue(None, "ListAgentRuntimeEndpoints", "AccessDenied")],
        relationships=[relationship()],
    )
    document = diagnostics(value)
    assert document["summary"]["recorded_relationships"] == 1
    assert document["relationship_coverage"]["observed_relationships"] == 1
    assert limitations(document)[0]["reason_code"] == "ACCESS_DENIED"
    assert document["services"][0]["coverage_status"] != "COMPLETE"


def test_duplicate_reordered_issues_have_identical_json_and_keep_multiplicity():
    issues = [
        CollectionIssue(None, "GetAgentRuntime", "AWS request throttled"),
        CollectionIssue(None, "ListAgentRuntimeEndpoints", "AccessDenied"),
        CollectionIssue(None, "ListAgentRuntimeEndpoints", "AccessDenied"),
    ]
    first = module().render_coverage_json(diagnostics(snapshot(service="iam", issues=issues)))
    second = module().render_coverage_json(diagnostics(snapshot(service="iam", issues=reversed(issues))))
    assert first == second
    assert first.count('"reason_code": "ACCESS_DENIED"') == 2


def test_report_must_match_snapshot_scan_account_and_region():
    value = snapshot()
    report = evaluate_snapshot(value)
    for metadata in (
        {**report.metadata, "scan_id": "other"},
        {**report.metadata, "account_id": "999999999999"},
        {**report.metadata, "region": "us-east-1"},
    ):
        with pytest.raises(ValueError, match="does not match"):
            module().build_coverage_diagnostics(value, replace(report, metadata=metadata))


def test_cli_help_json_console_exit_and_offline_zero_client(monkeypatch, tmp_path):
    runner = CliRunner()
    path = write(snapshot(), tmp_path / "facts.json")
    monkeypatch.setattr("boto3.session.Session.client", Mock(side_effect=AssertionError("AWS client")))
    help_result = runner.invoke(app, ["coverage", "--help"])
    assert help_result.exit_code == 0 and "offline" in help_result.stdout.lower()
    json_result = runner.invoke(app, ["coverage", str(path), "--output", "json"])
    assert json_result.exit_code == 0
    assert json.loads(json_result.stdout)["kind"] == "coverage-diagnostics"
    console = runner.invoke(app, ["coverage", str(path)])
    assert console.exit_code == 0 and "Completeness is not proven" in console.stdout


def test_root_help_and_readme_discover_conservative_coverage_command():
    root = CliRunner().invoke(app, ["--help"])
    assert root.exit_code == 0 and "awsherlock coverage facts.json" in root.stdout
    readme = Path("README.md").read_text(encoding="utf-8")
    for text in (
        "awsherlock coverage snapshot.json --output json",
        "coverage-diagnostics",
        "Missing Findings",
        "Missing Relationships",
    ):
        assert text in readme


def test_cli_invalid_snapshot_path_collision_and_exclusive_create(tmp_path):
    runner = CliRunner()
    malformed = tmp_path / "bad.json"
    malformed.write_text("{bad", encoding="utf-8")
    assert runner.invoke(app, ["coverage", str(malformed)]).exit_code == 1
    path = write(snapshot(), tmp_path / "facts.json")
    collision = runner.invoke(app, ["coverage", str(path), "--output", "json", "--report-file", str(path)])
    assert collision.exit_code == 1
    destination = tmp_path / "coverage.json"
    destination.write_text("KEEP", encoding="utf-8")
    exists = runner.invoke(app, ["coverage", str(path), "--output", "json", "--report-file", str(destination)])
    assert exists.exit_code == 1 and destination.read_text(encoding="utf-8") == "KEEP"
    assert runner.invoke(app, ["coverage", str(path), "--output", "html"]).exit_code == 2


def test_cli_incomplete_evidence_writes_diagnostics_and_exits_one(tmp_path):
    runner = CliRunner()
    value = snapshot(issues=[CollectionIssue(None, "ListBuckets", "AccessDenied")])
    path = write(value, tmp_path / "facts.json")
    destination = tmp_path / "coverage.json"
    result = runner.invoke(app, ["coverage", str(path), "--output", "json", "--report-file", str(destination)])
    assert result.exit_code == 1 and destination.exists()
    assert json.loads(destination.read_text(encoding="utf-8"))["summary"]["incomplete_services"] == 1


def test_console_sanitizes_untrusted_snapshot_metadata():
    value = snapshot()
    value.metadata = replace(value.metadata, scan_id="scan\x1b]8;;https://evil.invalid\x07link")
    rendered = module().render_coverage_console(diagnostics(value))
    assert "\x1b" not in rendered and "\x07" not in rendered
    assert r"scan\x1b]8;;https://evil.invalid\x07link" in rendered


def test_serial_parallel_reports_produce_same_diagnostics():
    value = snapshot(issues=[CollectionIssue(None, "ListBuckets", "AccessDenied")])
    parallel = deepcopy(value)
    parallel.services = dict(reversed(list(parallel.services.items())))
    assert module().render_coverage_json(diagnostics(value)) == module().render_coverage_json(diagnostics(parallel))


def test_diagnostics_do_not_change_lead_delta_or_evidence_pack_inputs():
    value = snapshot()
    before = value.to_dict()
    diagnostics(value)
    assert value.to_dict() == before


def test_builder_uses_supplied_evaluation_without_second_evaluation(monkeypatch):
    value = snapshot()
    report = evaluate_snapshot(value)
    monkeypatch.setattr(
        "awsherlock.evaluation.evaluate_snapshot",
        Mock(side_effect=AssertionError("second evaluation")),
    )
    assert module().build_coverage_diagnostics(value, report)["services"][0]["coverage_status"] == "COMPLETE"


def test_json_bytes_match_across_hash_seeds():
    script = r'''
from datetime import datetime,timezone
from awsherlock.collectors.common import CollectionIssue,CollectionResult
from awsherlock.coverage_intelligence import build_coverage_diagnostics,render_coverage_json
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.models import ScanMetadata
from awsherlock.snapshot import Snapshot
metadata=ScanMetadata(scan_id="fixed",started_at=datetime(2026,1,1,tzinfo=timezone.utc),account_id="123456789012",region="eu-central-1",version="0.5.0")
issues=[CollectionIssue(None,"ListAgentRuntimeEndpoints","AccessDenied"),CollectionIssue(None,"GetAgentRuntime","AWS request throttled")]
value=Snapshot(metadata,{"iam":CollectionResult([],list(reversed(issues)))},(),2)
print(render_coverage_json(build_coverage_diagnostics(value,evaluate_snapshot(value))),end="")
'''
    env = dict(os.environ, PYTHONPATH=str(Path("src").resolve()), PYTHONDONTWRITEBYTECODE="1")
    outputs = [subprocess.run([sys.executable, "-c", script], env={**env, "PYTHONHASHSEED": seed},
                              capture_output=True, text=True, check=True).stdout for seed in ("1", "777")]
    assert outputs[0] == outputs[1]
