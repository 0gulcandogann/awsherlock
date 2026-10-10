"""Offline minimized evidence exports over public synthetic Lead fixtures."""

from copy import deepcopy
from dataclasses import replace
import importlib
import json
import os
import subprocess
import sys
from html.parser import HTMLParser

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.collectors.common import CollectionIssue, CollectionResult
from awsherlock.models import RelationshipEvidence
from awsherlock.leads import investigation_leads
from awsherlock.snapshot import snapshot_from_dict
from test_lead_delta import pair, agentcore_snapshot, LAMBDA, EC2, OWNER, STALE, AI
from test_leads_v2 import ACCOUNT, REGION, function, role, group, runs_as, snapshot


def api():
    return importlib.import_module("awsherlock.investigation")


def selected(value, pattern=LAMBDA):
    return next(lead for lead in investigation_leads(value)["leads"] if lead["pattern_id"] == pattern)["lead_id"]


def source_file(tmp_path, value=None, pattern=LAMBDA):
    value = value or pair(pattern)
    path = tmp_path / "facts.json"
    path.write_text(json.dumps(value.to_dict()), encoding="utf-8")
    return path, selected(value, pattern)


@pytest.mark.parametrize("pattern", [LAMBDA, EC2, OWNER, STALE, AI])
def test_all_families_select_exactly_one_minimized_lead(pattern):
    value = pair(pattern)
    pack = api().build_evidence_pack(value, selected(value, pattern))
    assert pack["kind"] == "investigation-evidence-pack"
    assert pack["schema_version"] == 1
    assert pack["status"] == "COMPLETE"
    assert pack["lead"]["pattern_id"] == pattern
    assert pack["lead"]["lead_id"] == selected(value, pattern)
    assert pack["findings"] and pack["statements"]["observed"]
    assert pack["statements"]["unknown"] and pack["statements"]["not_proven"]
    assert pack["manual_steps"]
    assert "services" not in pack and '"data":' not in api().render_evidence_json(pack)


@pytest.mark.parametrize("selector", ["missing", "LAMBDA-URL-BROAD-ROLE", "LAMBDA-URL-BROAD-ROLE:708c"])
def test_unknown_prefix_or_fuzzy_id_fails(selector):
    with pytest.raises(api().InvestigationError):
        api().build_evidence_pack(pair(LAMBDA), selector)


@pytest.mark.parametrize("pattern", [LAMBDA, STALE])
def test_v1_finding_only_pack_reports_unsupported_relationships(pattern):
    value = pair(pattern, version=1)
    pack = api().build_evidence_pack(value, selected(value, pattern))
    assert pack["source_snapshot"]["schema_version"] == 1
    assert pack["relationships"] == []
    assert pack["status"] == "PARTIAL"
    assert "RELATIONSHIPS_UNSUPPORTED" in pack["limitations"]


def test_agentcore_relationship_only_version_identity_and_provenance():
    value = agentcore_snapshot("7")
    pack = api().build_evidence_pack(value, selected(value, AI))
    subject = pack["lead"]["subjects"][0]
    assert subject["resource_type"] == "runtime-version"
    assert subject["resource_id"] == "example-0123456789:7"
    assert subject["resource_arn"] is None
    assert pack["relationships"][0]["evidence"][0]["operation"] is None
    assert "API_OPERATION_UNAVAILABLE" in pack["limitations"]


@pytest.mark.parametrize("damage", ["duplicate", "findings", "relationships", "subject_arn"])
def test_inconsistent_selected_lead_fails_before_export(monkeypatch, damage):
    module = api()
    value = pair(EC2)
    lead_id = selected(value, EC2)
    real = module.investigation_leads

    def corrupt(value, **kwargs):
        document = deepcopy(real(value, **kwargs))
        lead = next(item for item in document["leads"] if item["lead_id"] == lead_id)
        if damage == "duplicate":
            document["leads"].append(deepcopy(lead))
        elif damage == "subject_arn":
            lead["subjects"][0]["resource_arn"] += "-foreign"
        else:
            lead[damage] = []
        return document

    monkeypatch.setattr(module, "investigation_leads", corrupt)
    with pytest.raises(module.InvestigationError):
        module.build_evidence_pack(value, lead_id)


def test_missing_resolved_finding_is_fatal(monkeypatch):
    module = api()
    value = pair(LAMBDA)
    lead_id = selected(value)
    document = investigation_leads(value)
    real = module.evaluate_snapshot

    def missing(value):
        report = real(value)
        report.findings = [f for f in report.findings if f.id != "AWSH-LAMBDA-001"]
        return report

    monkeypatch.setattr(module, "evaluate_snapshot", missing)
    monkeypatch.setattr(module, "investigation_leads", lambda *args, **kwargs: document)
    with pytest.raises(module.InvestigationError):
        module.build_evidence_pack(value, lead_id)


@pytest.mark.parametrize("foreign", [
    f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:other",
    f"arn:aws:lambda:{REGION}:999999999999:function:fn",
    f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:fn",
    f"arn:aws-us-gov:lambda:{REGION}:{ACCOUNT}:function:fn",
])
def test_foreign_lambda_url_cannot_be_exported(foreign):
    value = pair(LAMBDA)
    value.services["lambda"].resources[0].data["urls"][0]["arn"] = foreign
    value = snapshot_from_dict(value.to_dict())
    with pytest.raises(api().InvestigationError, match="LAMBDA_URL_IDENTITY_MISMATCH"):
        api().build_evidence_pack(value, selected(value))


@pytest.mark.parametrize("qualifier", ["live", "1"])
def test_qualified_lambda_url_is_supported(qualifier):
    value = pair(LAMBDA)
    value.services["lambda"].resources[0].data["urls"][0]["arn"] += ":" + qualifier
    pack = api().build_evidence_pack(value, selected(value))
    assert pack["status"] == "COMPLETE"


def test_group_cannot_supply_role_finding_via_shared_arn():
    narrow = role(stale=True, broad_check="none")
    collision = replace(group(), resource_arn=narrow.resource_arn)
    value = snapshot_from_dict(snapshot([narrow, collision], version=2).to_dict())
    with pytest.raises(api().InvestigationError, match="AMBIGUOUS_RESOURCE_IDENTITY"):
        api().build_evidence_pack(value, selected(value, STALE))


@pytest.mark.parametrize("scope", ["account", "region"])
def test_same_named_foreign_scope_never_supplies_evidence(scope):
    value = pair(LAMBDA)
    lead_id = selected(value)
    fn = value.services["lambda"].resources[0]
    foreign = replace(fn, account_id="999999999999") if scope == "account" else replace(fn, region="us-east-1")
    value.services["lambda"].resources.append(foreign)
    # Identical ARN on a distinct logical scope is never a valid exact join.
    with pytest.raises(api().InvestigationError):
        api().build_evidence_pack(value, lead_id)


def test_unrelated_resources_findings_relationships_and_secrets_are_excluded():
    value = pair(LAMBDA)
    other = function("unrelated-name")
    value.services["lambda"].resources.append(other)
    value.relationships += (runs_as(other, value.services["iam"].resources[0]),)
    # A valid but unnecessary policy locator must not leak from resource facts.
    value.services["iam"].resources[0].data["identity_profile"]["boundary"] = (
        f"arn:aws:iam::{ACCOUNT}:policy/SECRET_SENTINEL")
    pack = api().build_evidence_pack(value, selected(value))
    encoded = api().render_evidence_json(pack)
    assert "SECRET_SENTINEL" not in encoded and "unrelated-name" not in encoded
    assert {f["check_id"] for f in pack["findings"]} == {"AWSH-LAMBDA-001", "AWSH-LAMBDA-002"}
    assert len(pack["relationships"]) == 1


def test_secret_bearing_snapshot_fails_safely_without_artifact(tmp_path):
    value = pair(LAMBDA)
    lead_id = selected(value)
    raw = value.to_dict()
    raw["services"]["lambda"]["resources"][0]["data"]["environment"] = {"secret_access_key": "SECRET_SENTINEL"}
    path = tmp_path / "secret-facts.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    destination = tmp_path / "pack.html"
    result = CliRunner().invoke(app, ["investigate", str(path), "--lead-id", lead_id,
        "--output", "html", "--report-file", str(destination)])
    assert result.exit_code == 1 and not destination.exists()
    assert "SECRET_SENTINEL" not in result.output


def test_nested_normalized_finding_payload_is_allowlisted(monkeypatch):
    module = api()
    value = pair(STALE)
    real = module.evaluate_snapshot

    def secrets(value):
        report = real(value)
        for finding in report.findings:
            if finding.id == "AWSH-IAM-009":
                finding.evidence["identity_usage"]["secret"] = "SECRET_SENTINEL"
                finding.evidence["raw_sdk_response"] = "SECRET_SENTINEL"
        return report

    monkeypatch.setattr(module, "evaluate_snapshot", secrets)
    pack = module.build_evidence_pack(value, selected(value, STALE))
    assert "SECRET_SENTINEL" not in module.render_evidence_json(pack)


def test_partial_policy_context_and_relevant_diagnostics_are_honest_and_minimized():
    value = pair(EC2)
    value.services["iam"].resources[0].data["identity_policy_context"]["complete"] = False
    value.services["iam"].issues.append(CollectionIssue("worker", "GetRolePolicy", "AccessDenied SECRET_SENTINEL"))
    pack = api().build_evidence_pack(value, selected(value, EC2))
    assert pack["status"] == "PARTIAL"
    assert "IAM_POLICY_CONTEXT_INCOMPLETE" in pack["limitations"]
    encoded = api().render_evidence_json(pack)
    assert "SECRET_SENTINEL" not in encoded
    assert "AccessDenied" in encoded or "ACCESS_DENIED" in encoded
    assert "not proven" in encoded.lower()


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


@pytest.mark.parametrize("payload", ['<script>alert(1)</script>', '<svg onload="alert(1)">', '\"><img src=x onerror=alert(1)>'])
def test_html_escapes_aws_and_evidence_strings(payload):
    value = pair(LAMBDA)
    value.metadata = replace(value.metadata, scan_id=payload)
    rendered = api().render_evidence_html(api().build_evidence_pack(value, selected(value)))
    parsed = Tags()
    parsed.feed(rendered)
    assert not {"script", "svg", "img", "iframe", "object"} & {tag for tag, _ in parsed.tags}
    assert payload not in rendered and "&lt;" in rendered


@pytest.mark.parametrize("url", ["javascript:alert(1)", "http://example.com", "https://user@example.com", "https://example.com:443/a", "https://example.com\\evil"])
def test_unsafe_urls_are_not_clickable(url):
    pack = api().build_evidence_pack(pair(LAMBDA), selected(pair(LAMBDA)))
    pack["findings"][0]["references"] = [url]
    parsed = Tags()
    parsed.feed(api().render_evidence_html(pack))
    assert all(attrs.get("href") != url for tag, attrs in parsed.tags if tag == "a")


def test_safe_links_are_private_and_static_html_has_no_network_assets():
    pack = api().build_evidence_pack(pair(LAMBDA), selected(pair(LAMBDA)))
    parsed = Tags()
    parsed.feed(api().render_evidence_html(pack))
    assert any(tag == "a" for tag, attrs in parsed.tags)
    for tag, attrs in parsed.tags:
        assert tag not in {"script", "link", "img", "iframe"}
        if tag == "a":
            assert attrs["rel"] == "noopener noreferrer" and attrs["referrerpolicy"] == "no-referrer"


def test_pack_is_deterministic_and_does_not_mutate_input():
    value = pair(EC2)
    saved = deepcopy(value.to_dict())
    first = api().build_evidence_pack(value, selected(value, EC2))
    value.relationships = tuple(reversed(value.relationships))
    value.services["iam"].resources[0].data["attached"].reverse()
    second = api().build_evidence_pack(value, selected(value, EC2))
    assert api().render_evidence_json(first) == api().render_evidence_json(second)
    assert api().render_evidence_html(first) == api().render_evidence_html(second)
    assert saved == value.to_dict()


def test_pipeline_evaluates_and_correlates_once_with_exact_report(monkeypatch):
    module = api()
    value = pair(LAMBDA)
    lead_id = selected(value)
    real_evaluate, real_correlate = module.evaluate_snapshot, module.investigation_leads
    evaluated, correlated = [], []

    def evaluate(value):
        report = real_evaluate(value)
        evaluated.append(report)
        return report

    def correlate(value, *, report):
        assert report is evaluated[0]
        correlated.append(report)
        return real_correlate(value, report=report)

    monkeypatch.setattr(module, "evaluate_snapshot", evaluate)
    monkeypatch.setattr(module, "investigation_leads", correlate)
    assert module.build_evidence_pack(value, lead_id)["lead"]["lead_id"] == lead_id
    assert len(evaluated) == len(correlated) == 1


@pytest.mark.parametrize("output", ["json", "html"])
@pytest.mark.parametrize("partial", [False, True])
def test_cli_offline_export_and_partial_exit(tmp_path, monkeypatch, output, partial):
    import boto3
    import botocore.session
    from awsherlock.aws.context import ScanContext

    def forbidden(*args, **kwargs):
        pytest.fail("Offline evidence export attempted AWS access")

    for obj, name in [(boto3, "Session"), (boto3.session, "Session"), (boto3, "client"),
                      (botocore.session, "get_session"), (ScanContext, "client")]:
        monkeypatch.setattr(obj, name, forbidden)
    value = pair(LAMBDA)
    if partial:
        value.services["lambda"].issues.append(CollectionIssue("fn", "ListFunctionUrlConfigs", "AccessDenied"))
    path, lead_id = source_file(tmp_path, value)
    saved = path.read_bytes()
    args = ["investigate", str(path), "--lead-id", lead_id, "--output", output]
    destination = tmp_path / "pack.html"
    if output == "html":
        args.extend(["--report-file", str(destination)])
    result = CliRunner().invoke(app, args)
    assert result.exit_code == (1 if partial else 0), result.output
    assert path.read_bytes() == saved
    if output == "html":
        assert "Investigation Evidence Pack" in destination.read_text(encoding="utf-8")
    else:
        assert json.loads(result.stdout)["status"] == ("PARTIAL" if partial else "COMPLETE")


@pytest.mark.parametrize("output", ["json", "html"])
@pytest.mark.parametrize("failure", ["existing", "collision", "unknown"])
def test_cli_fatal_errors_never_write_or_overwrite(tmp_path, output, failure):
    path, lead_id = source_file(tmp_path)
    destination = path if failure == "collision" else tmp_path / "pack.out"
    if failure == "existing":
        destination.write_text("DO_NOT_OVERWRITE", encoding="utf-8")
    saved = destination.read_bytes() if destination.exists() else None
    result = CliRunner().invoke(app, ["investigate", str(path), "--lead-id", lead_id if failure != "unknown" else "missing",
                                    "--output", output, "--report-file", str(destination)])
    assert result.exit_code == 1, result.output
    if saved is None:
        assert not destination.exists()
    else:
        assert destination.read_bytes() == saved


@pytest.mark.parametrize("args", [["investigate"], ["investigate", "x.json"],
    ["investigate", "x.json", "--lead-id", "x", "--output", "html"],
    ["investigate", "x.json", "--lead-id", "x", "--output", "xml"]])
def test_cli_usage_errors_exit_two(args):
    assert CliRunner().invoke(app, args).exit_code == 2


@pytest.mark.parametrize("args", [["--help"], ["investigate", "--help"]])
def test_help_discovers_offline_investigation(args):
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0 and "investigate" in result.output.lower()
    if args[0] == "investigate":
        assert "--lead-id" in result.output and "--report-file" in result.output


def test_installed_cli_and_pack_template_subprocess(tmp_path):
    path, lead_id = source_file(tmp_path)
    destination = tmp_path / "pack.html"
    result = subprocess.run([sys.executable, "-m", "awsherlock", "investigate", str(path), "--lead-id", lead_id,
        "--output", "html", "--report-file", str(destination)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "Investigation Evidence Pack" in destination.read_text(encoding="utf-8")


def test_hash_seed_json_and_html_bytes_match():
    script = """import sys,json; sys.path.insert(0,'tests')
from test_investigation import api,selected,operation_snapshot
from test_lead_delta import pair,EC2
outputs=[]
for s in [pair(EC2),operation_snapshot('relationship','SecretMarker123'),operation_snapshot('coverage','SecretMarker123')]:
    p=api().build_evidence_pack(s,selected(s,EC2))
    outputs.append([api().render_evidence_json(p),api().render_evidence_html(p)])
print(json.dumps(outputs))
"""
    outputs = [subprocess.check_output([sys.executable, "-c", script],
        env={**os.environ, "PYTHONHASHSEED": seed}) for seed in ["1", "777"]]
    assert outputs[0] == outputs[1]
    assert b"SecretMarker123" not in outputs[0]


@pytest.mark.parametrize("check", ["AWSH-IAM-001", "AWSH-IAM-002", "AWSH-IAM-003"])
def test_normalized_broad_policy_projection_is_narrow(check):
    value = snapshot([role(stale=True, broad_check=check)], version=2)
    pack = api().build_evidence_pack(value, selected(value, STALE))
    broad = next(f for f in pack["findings"] if f["check_id"] == check)
    assert set(broad["evidence"]) == ({"attached"} if check.endswith("001") else {"statements"})
    if check.endswith("001"):
        assert broad["evidence"]["attached"] == ["arn:aws:iam::aws:policy/AdministratorAccess"]
    else:
        assert set(broad["evidence"]["statements"][0]) == {
            "effect", "conditional", "actions", "resources", "not_actions", "not_resources"}


def test_regional_coverage_identity_is_preserved():
    value = pair(LAMBDA)
    pack = api().build_evidence_pack(value, selected(value))
    assert next(row for row in pack["coverage"] if row["service"] == "lambda")["region"] == REGION
    assert next(row for row in pack["coverage"] if row["service"] == "iam")["region"] is None


@pytest.mark.parametrize("damage", ["missing_edge", "foreign_role_path", "conflicting_ai_role"])
def test_resolved_relationship_and_role_identity_damage_is_fatal(monkeypatch, damage):
    module = api()
    value = pair(AI)
    lead_id = selected(value, AI)
    document = investigation_leads(value)
    if damage == "missing_edge":
        value.relationships = ()
        monkeypatch.setattr(module, "investigation_leads", lambda *args, **kwargs: document)
    elif damage == "foreign_role_path":
        edge = value.relationships[0]
        value.relationships = (replace(edge, target=replace(edge.target,
            resource_arn=f"arn:aws:iam::{ACCOUNT}:role/foreign-path/worker")),)
    else:
        value.services["bedrock"].resources[0].data["execution_role_arn"] = f"arn:aws:iam::{ACCOUNT}:role/other"
    with pytest.raises(module.InvestigationError):
        module.build_evidence_pack(value, lead_id)


def test_required_relationship_must_connect_selected_subject(monkeypatch):
    module = api()
    value = pair(EC2)
    extra = function("other")
    value.services["lambda"] = CollectionResult([extra])
    value.relationships += (runs_as(extra, value.services["iam"].resources[0]),)
    lead_id = selected(value, EC2)
    real = module.investigation_leads

    def corrupt(value, **kwargs):
        doc = real(value, **kwargs)
        lead = next(item for item in doc["leads"] if item["lead_id"] == lead_id)
        from awsherlock.relationships import relationship_to_dict
        unrelated = relationship_to_dict(value.relationships[-1])
        lead["relationships"] = [{key: unrelated[key] for key in ("source", "type", "target")}]
        return doc

    monkeypatch.setattr(module, "investigation_leads", corrupt)
    with pytest.raises(module.InvestigationError):
        module.build_evidence_pack(value, lead_id)


@pytest.mark.parametrize("payload", ['<script>alert(1)</script>', '<svg/onload=alert(1)>', '"onload="alert(1)'])
def test_html_escapes_real_iam_path_locator(payload):
    value = snapshot([replace(role(stale=True), resource_arn=f"arn:aws:iam::{ACCOUNT}:role/{payload}/worker")], version=2)
    rendered = api().render_evidence_html(api().build_evidence_pack(value, selected(value, STALE)))
    parsed = Tags()
    parsed.feed(rendered)
    assert not {"script", "svg", "img"} & {tag for tag, attrs in parsed.tags}
    assert not any(name.startswith("on") for _, attrs in parsed.tags for name in attrs)


def test_unrelated_service_coverage_does_not_make_pack_partial():
    from awsherlock.collectors.common import CollectionResult
    value = pair(LAMBDA)
    value.services["s3"] = CollectionResult([], [CollectionIssue(None, "ListBuckets", "AccessDenied")])
    pack = api().build_evidence_pack(value, selected(value))
    assert pack["status"] == "COMPLETE"
    assert {row["service"] for row in pack["coverage"]} == {"lambda", "iam"}


@pytest.mark.parametrize("schema", [0, 3])
def test_unsupported_snapshot_cli_does_not_write(tmp_path, schema):
    value = pair(LAMBDA)
    raw = value.to_dict()
    raw["schema_version"] = schema
    path = tmp_path / "unsupported.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    destination = tmp_path / "pack.html"
    result = CliRunner().invoke(app, ["investigate", str(path), "--lead-id", selected(value),
        "--output", "html", "--report-file", str(destination)])
    assert result.exit_code == 1 and not destination.exists()


@pytest.mark.parametrize("output", ["json", "html"])
def test_foreign_url_cli_fatal_resolution_leaves_no_artifact(tmp_path, output):
    value = pair(LAMBDA)
    lead_id = selected(value)
    value.services["lambda"].resources[0].data["urls"][0]["arn"] = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:other"
    path = tmp_path / "foreign.json"
    path.write_text(json.dumps(value.to_dict()), encoding="utf-8")
    destination = tmp_path / "pack.out"
    result = CliRunner().invoke(app, ["investigate", str(path), "--lead-id", lead_id,
        "--output", output, "--report-file", str(destination)])
    assert result.exit_code == 1 and not destination.exists()


@pytest.mark.parametrize("location", ["coverage", "relationship_operation", "relationship_fact"])
@pytest.mark.parametrize("output", ["json", "html"])
def test_arbitrary_provenance_text_is_not_exported(location, output):
    value = pair(EC2)
    if location == "coverage":
        value.services["iam"].issues.append(CollectionIssue("worker", "AccessDenied SECRET_SENTINEL", "AccessDenied"))
    else:
        edge = value.relationships[0]
        evidence = RelationshipEvidence(service="iam", fact="secret_sentinel" if location.endswith("fact") else "identity_bindings",
            operation="AccessDenied SECRET_SENTINEL" if location.endswith("operation") else None)
        value.relationships = (replace(edge, evidence=(evidence,)),)
    value = snapshot_from_dict(value.to_dict())
    pack = api().build_evidence_pack(value, selected(value, EC2))
    rendered = api().render_evidence_json(pack) if output == "json" else api().render_evidence_html(pack)
    assert "secret_sentinel" not in rendered.lower()
    assert pack["status"] == "PARTIAL"
    assert "PROVENANCE_FIELD_UNAVAILABLE" in pack["limitations"]


def test_legitimate_stored_operation_is_preserved():
    value = pair(AI)
    edge = value.relationships[0]
    value.relationships = (replace(edge, evidence=(RelationshipEvidence(service="bedrock",
        fact="execution_role_arn", operation="GetAgent"),)),)
    pack = api().build_evidence_pack(value, selected(value, AI))
    assert pack["relationships"][0]["evidence"][0] == {
        "service": "bedrock", "fact": "execution_role_arn", "operation": "GetAgent"}
    assert pack["status"] == "COMPLETE"


def test_standalone_evidence_pack_opens_in_browser(tmp_path):
    from test_report_browser import run_browser
    value = pair(LAMBDA)
    pack = api().build_evidence_pack(value, selected(value))
    rendered = api().render_evidence_html(pack)
    output = run_browser(rendered, "", tmp_path)
    assert pack["lead"]["lead_id"] in output
    assert 'id="findings"' in output and 'id="not_proven"' in output
    assert '<script>' not in rendered and '<svg' not in rendered


def operation_snapshot(location, operation):
    """Accepted source evidence with one operation export under test."""
    value = pair(EC2)
    if location == "coverage":
        value.services["iam"].issues.append(CollectionIssue("worker", operation, "AccessDenied"))
    else:
        edge = value.relationships[0]
        value.relationships = (replace(edge, evidence=(RelationshipEvidence(
            service="iam", fact="identity_bindings", operation=operation),)),)
    return snapshot_from_dict(value.to_dict())


@pytest.mark.parametrize("marker", ["SecretMarker123", "GetSecretMarker123", "DescribeSecretMarker777"])
@pytest.mark.parametrize("location", ["relationship", "coverage"])
@pytest.mark.parametrize("output", ["json", "html"])
def test_operation_allowlist_excludes_identifier_shaped_payloads(marker, location, output):
    value = operation_snapshot(location, marker)
    lead_id = selected(value, EC2)
    pack = api().build_evidence_pack(value, lead_id)
    rendered = api().render_evidence_json(pack) if output == "json" else api().render_evidence_html(pack)
    assert marker not in rendered
    assert pack["status"] == "PARTIAL"
    assert "PROVENANCE_FIELD_UNAVAILABLE" in pack["limitations"]
    assert pack["lead"]["lead_id"] == lead_id
    assert {f["check_id"] for f in pack["findings"]} == {"AWSH-EC2-004", "AWSH-EC2-005", "AWSH-IAM-001"}
    assert len(pack["relationships"]) == 1 and pack["statements"]["observed"]
    target = (pack["relationships"][0]["evidence"][0] if location == "relationship" else
              next(row for row in pack["coverage"] if row["service"] == "iam")["issues"][0])
    assert target["operation"] is None


@pytest.mark.parametrize("location", ["relationship", "coverage"])
def test_operation_allowlist_rejects_wrong_context_and_casing(location):
    # GetAgent is recognized for Bedrock, not IAM-role/EC2 binding evidence.
    for operation in ("GetAgent", "getrole", "GetRolePolicyUnexpected"):
        value = operation_snapshot(location, operation)
        pack = api().build_evidence_pack(value, selected(value, EC2))
        assert "PROVENANCE_FIELD_UNAVAILABLE" in pack["limitations"]
        assert operation not in api().render_evidence_json(pack)


@pytest.mark.parametrize("pattern,service,operation", [
    (EC2, "ec2", "describe_instances.metadata"),
    (EC2, "ec2", "describe_instances"),
    (LAMBDA, "lambda", "ListFunctionUrlConfigs"),
    (LAMBDA, "lambda", "ListAttachedRolePolicies"),
    (LAMBDA, "lambda", "ManagedRuntime (images/unknown runtimes not scanned)"),
    (EC2, "iam", "GetRolePolicy"),
    (EC2, "iam", "IdentityManagedPolicy"),
    (EC2, "iam", "RoleLastUsed"),
    (EC2, "iam", f"IdentityBindings:ec2:{REGION}"),
    (AI, "bedrock", "GetAgent"),
])
def test_operation_allowlist_preserves_real_collection_labels(pattern, service, operation):
    value = pair(pattern)
    value.services[service].issues.append(CollectionIssue(None, operation, "AccessDenied"))
    value = snapshot_from_dict(value.to_dict())
    pack = api().build_evidence_pack(value, selected(value, pattern))
    issues = next(row for row in pack["coverage"] if row["service"] == service)["issues"]
    assert any(issue["operation"] == operation for issue in issues)
    assert "PROVENANCE_FIELD_UNAVAILABLE" not in pack["limitations"]
    assert pack["status"] == "PARTIAL" and pack["findings"] and pack["relationships"]


@pytest.mark.parametrize("pattern,service,fact,operation", [
    (LAMBDA, "iam", "identity_bindings", "ListFunctions"),
    (EC2, "iam", "identity_bindings", "DescribeInstances"),
    (EC2, "iam", "identity_bindings", "GetInstanceProfile"),
    (EC2, "iam", "identity_bindings", "GetRole"),
    (AI, "iam", "identity_bindings", "GetAgent"),
    (AI, "bedrock", "execution_role_arn", "GetAgent"),
])
def test_operation_allowlist_preserves_attributed_relationship_operations(pattern, service, fact, operation):
    value = pair(pattern)
    edge = value.relationships[0]
    value.relationships = (replace(edge, evidence=(RelationshipEvidence(
        service=service, fact=fact, operation=operation),)),)
    value = snapshot_from_dict(value.to_dict())
    pack = api().build_evidence_pack(value, selected(value, pattern))
    assert pack["relationships"][0]["evidence"][0] == {"service": service, "fact": fact, "operation": operation}
    assert pack["status"] == "COMPLETE"


@pytest.mark.parametrize("operation", [None, "ListAgentRuntimes", "GetAgentRuntime"])
def test_operation_allowlist_preserves_agentcore_and_historical_null(operation):
    value = agentcore_snapshot("7")
    edge = value.relationships[0]
    value.relationships = (replace(edge, evidence=(RelationshipEvidence(
        service="iam", fact="identity_bindings", operation=operation),)),)
    pack = api().build_evidence_pack(value, selected(value, AI))
    assert pack["relationships"][0]["evidence"][0]["operation"] == operation
    assert pack["status"] == "COMPLETE"
    assert "PROVENANCE_FIELD_UNAVAILABLE" not in pack["limitations"]


@pytest.mark.parametrize("location", ["relationship", "coverage"])
@pytest.mark.parametrize("output", ["json", "html"])
def test_operation_allowlist_cli_partial_exit_and_source_integrity(tmp_path, location, output):
    value = operation_snapshot(location, "SecretMarker123")
    source, lead_id = source_file(tmp_path, value, EC2)
    original = source.read_bytes()
    target = tmp_path / "pack.out"
    args = ["investigate", str(source), "--lead-id", lead_id, "--output", output]
    if output == "html":
        args += ["--report-file", str(target)]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 1
    rendered = target.read_text(encoding="utf-8") if output == "html" else result.stdout
    assert "SecretMarker123" not in rendered and "PROVENANCE_FIELD_UNAVAILABLE" in rendered
    assert "PARTIAL" in rendered and lead_id in rendered
    assert source.read_bytes() == original
    pack = api().build_evidence_pack(value, lead_id)
    assert api().render_evidence_json(pack) == api().render_evidence_json(api().build_evidence_pack(value, lead_id))
    assert api().render_evidence_html(pack) == api().render_evidence_html(api().build_evidence_pack(value, lead_id))


def test_operation_allowlist_unrelated_coverage_does_not_contaminate_pack():
    value = pair(LAMBDA)
    value.services["s3"] = CollectionResult([], [CollectionIssue(None, "SecretMarker123", "AccessDenied")])
    value.services["iam"].issues.append(CollectionIssue("unrelated", "SecretMarker123", "AccessDenied"))
    pack = api().build_evidence_pack(value, selected(value))
    assert "SecretMarker123" not in api().render_evidence_json(pack)
    assert "SecretMarker123" not in api().render_evidence_html(pack)
    assert "PROVENANCE_FIELD_UNAVAILABLE" not in pack["limitations"]
    # Same-service coverage stays conservatively incomplete; unrelated s3 is excluded.
    assert pack["status"] == "PARTIAL"
    assert "s3" not in {row["service"] for row in pack["coverage"]}


@pytest.mark.parametrize("operation", [f"IdentityBindings:s3:{REGION}", "IdentityBindings:ec2:us-east-1"])
def test_operation_allowlist_rejects_unrelated_binding_diagnostic_scope(operation):
    value = operation_snapshot("coverage", operation)
    pack = api().build_evidence_pack(value, selected(value, EC2))
    assert "PROVENANCE_FIELD_UNAVAILABLE" in pack["limitations"]
    assert operation not in api().render_evidence_json(pack)
    assert operation not in api().render_evidence_html(pack)
    assert pack["status"] == "PARTIAL" and pack["findings"] and pack["relationships"]
