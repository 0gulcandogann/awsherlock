from dataclasses import replace
from copy import deepcopy
from datetime import datetime, timezone
import pytest

from awsherlock.collectors.common import CollectionResult
from awsherlock.evaluation import Report, evaluate_snapshot
from awsherlock.html_report import HtmlScope, build_html_view
from awsherlock.models import (
    Relationship,
    RelationshipEvidence,
    RelationshipType,
    Resource,
    ResourceRef,
    ScanMetadata,
)
from awsherlock.reporting import render_html
from awsherlock.snapshot import Snapshot, SnapshotError, write_snapshot
from awsherlock.cli import app
from typer.testing import CliRunner
from unittest.mock import Mock


ACCOUNT = "123456789012"
REGION = "us-east-1"


def role(name: str = "worker", *, broad: bool = True) -> Resource:
    return Resource(
        service="iam", resource_type="role", account_id=ACCOUNT, region=None,
        resource_id=name, resource_arn=f"arn:aws:iam::{ACCOUNT}:role/{name}",
        data={
            "attached": (["arn:aws:iam::aws:policy/AdministratorAccess"] if broad else []),
            "statements": ([{"effect": "Allow", "conditional": False,
                             "actions": ["*"], "resources": ["*"],
                             "not_actions": False, "not_resources": False}]
                           if broad else []),
        },
    )


def snapshot(*, version: int = 2, reverse: bool = False) -> Snapshot:
    target = role()
    source = ResourceRef(
        service="agentcore", resource_type="runtime-version", account_id=ACCOUNT,
        region=REGION, resource_id="Runtime_Example-abcdefghij:2", resource_arn=None,
    )
    target_ref = ResourceRef(
        service="iam", resource_type="role", account_id=ACCOUNT, region=None,
        resource_id="worker", resource_arn=target.resource_arn,
    )
    edge = Relationship(
        source=source, relationship_type=RelationshipType.RUNS_AS, target=target_ref,
        evidence=(RelationshipEvidence(service="iam", fact="identity_bindings"),),
    )
    resources = [target, role("observer", broad=False)]
    if reverse:
        resources.reverse()
    services = {"iam": CollectionResult(resources=resources)}
    return Snapshot(
        ScanMetadata(scan_id="m6", started_at=datetime(2026, 10, 8, tzinfo=timezone.utc),
                     account_id=ACCOUNT, region=REGION, version="test"),
        services, (edge,) if version == 2 else (), version,
    )


def test_render_html_without_investigation_context_remains_supported():
    report = evaluate_snapshot(snapshot())
    html = render_html(report)
    assert "Investigation context unavailable" in html
    assert "Findings" in html and "Scan coverage" in html


def test_view_links_agentcore_dangling_subject_to_relationship_and_finding():
    value = snapshot()
    report = evaluate_snapshot(value)
    view = build_html_view(report, (HtmlScope(snapshot=value, report=report),))

    assert view["relationship_capability"] == "supported"
    assert len(view["leads"]) == 1
    lead = view["leads"][0]
    assert lead["priority"] == "MEDIUM"
    assert lead["subjects"][0]["reference_kind"] == "relationship-only"
    assert lead["subjects"][0]["runtime_id"] == "Runtime_Example-abcdefghij"
    assert lead["subjects"][0]["runtime_version"] == "2"
    assert lead["relationships"][0]["href"].startswith("#relationship-")
    assert lead["findings"][0]["href"].startswith("#finding-")
    assert view["relationships"][0]["source"]["reference_kind"] == "relationship-only"


def test_v1_relationship_capability_is_unsupported_not_empty():
    value = snapshot(version=1)
    report = evaluate_snapshot(value)
    view = build_html_view(report, (HtmlScope(snapshot=value, report=report),))
    assert view["relationship_capability"] == "unsupported"
    assert view["relationships"] == []


def test_v2_zero_relationships_is_supported_and_not_a_pass_claim():
    value = snapshot()
    value.relationships = ()
    report = evaluate_snapshot(value)
    html = render_html(report, scopes=(HtmlScope(value, report),))
    assert "No positive relationships recorded" in html
    assert "not proof that no relationships exist" in html


def test_selected_check_report_cannot_supply_excluded_lead_findings():
    value = snapshot()
    report = evaluate_snapshot(value, selected_checks=["AWSH-IAM-007"])
    html = render_html(report, scopes=(HtmlScope(value, report),))
    assert "AI-WORKLOAD-BROAD-EXECUTION-ROLE" not in html


def test_v1_finding_only_lambda_lead_remains_eligible():
    arn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:classic"
    function = Resource(
        service="lambda", resource_type="function", account_id=ACCOUNT, region=REGION,
        resource_id="classic", resource_arn=arn,
        data={
            "urls": [{"arn": arn, "auth": "NONE"}],
            "role_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
            "runtime": {"name": "python3.13", "deprecated": False,
                        "catalog_date": "2026-09-15", "evaluated_on": "2026-10-08"},
        },
    )
    value = Snapshot(snapshot().metadata, {"lambda": CollectionResult(resources=[function])}, (), 1)
    report = evaluate_snapshot(value)
    html = render_html(report, scopes=(HtmlScope(value, report),))
    assert "LAMBDA-URL-BROAD-ROLE" in html
    assert "Relationships are unsupported by this snapshot version" in html


@pytest.mark.parametrize(
    ("metadata_field", "different_value"),
    (("account_id", "999999999999"), ("region", "eu-west-1")),
)
def test_scope_report_must_match_snapshot_account_and_region(metadata_field, different_value):
    value = snapshot()
    report = evaluate_snapshot(value)
    report.metadata[metadata_field] = different_value
    with pytest.raises(SnapshotError, match="does not match"):
        build_html_view(report, (HtmlScope(value, report),))


def test_scope_report_from_different_scan_cannot_supply_ai_lead_findings():
    relationship_snapshot = snapshot()
    finding_snapshot = snapshot()
    finding_snapshot.metadata = replace(finding_snapshot.metadata, scan_id="different-scan")
    finding_snapshot.relationships = ()
    finding_report = evaluate_snapshot(finding_snapshot)

    with pytest.raises(SnapshotError, match="does not match"):
        build_html_view(
            finding_report,
            (HtmlScope(relationship_snapshot, finding_report),),
        )


@pytest.mark.parametrize("invalid_scan_id", (None, "", 7))
def test_scope_report_requires_valid_scan_identity(invalid_scan_id):
    value = snapshot()
    report = evaluate_snapshot(value)
    report.metadata["scan_id"] = invalid_scan_id

    with pytest.raises(SnapshotError, match="does not match"):
        build_html_view(report, (HtmlScope(value, report),))


def test_scope_report_requires_present_scan_identity():
    value = snapshot()
    report = evaluate_snapshot(value)
    del report.metadata["scan_id"]

    with pytest.raises(SnapshotError, match="does not match"):
        build_html_view(report, (HtmlScope(value, report),))


def test_build_html_view_does_not_mutate_report_metadata():
    value = snapshot()
    report = evaluate_snapshot(value)
    report.metadata["accounts"] = [
        {"account_id": "999999999999", "name": "z", "state": "ACTIVE"},
        {"account_id": "111111111111", "name": "a", "state": "ACTIVE"},
    ]
    before = deepcopy(report.metadata)
    build_html_view(report, (HtmlScope(value, report),))
    assert report.metadata == before


def test_multi_account_scopes_do_not_cross_link_same_named_roles():
    first = snapshot()
    second_account = "999999999999"
    second = snapshot()
    second.metadata = replace(second.metadata, account_id=second_account, scan_id="m6-other")
    second.services["iam"].resources = [replace(
        item, account_id=second_account,
        resource_arn=item.resource_arn.replace(ACCOUNT, second_account),
    ) for item in second.services["iam"].resources]
    original_edge = second.relationships[0]
    second.relationships = (replace(
        original_edge,
        source=replace(original_edge.source, account_id=second_account),
        target=replace(original_edge.target, account_id=second_account,
                       resource_arn=original_edge.target.resource_arn.replace(ACCOUNT, second_account)),
    ),)
    reports = (evaluate_snapshot(first), evaluate_snapshot(second))
    aggregate = Report(
        {**reports[0].metadata, "region": None, "regions": [REGION]},
        reports[0].findings + reports[1].findings,
        reports[0].coverage + reports[1].coverage,
    )
    view = build_html_view(aggregate, (HtmlScope(first, reports[0]), HtmlScope(second, reports[1])))
    assert len(view["leads"]) == 2
    assert len({item["anchor"] for item in view["leads"]}) == 2
    assert {item["subjects"][0]["account_id"] for item in view["leads"]} == {
        ACCOUNT, second_account,
    }
    assert all(item["findings"] and all(ref["resolved"] for ref in item["findings"])
               for item in view["leads"])


def test_html_view_and_rendering_are_permutation_stable():
    first = snapshot()
    second = snapshot(reverse=True)
    first_report = evaluate_snapshot(first)
    second_report = evaluate_snapshot(second)
    assert render_html(first_report, scopes=(HtmlScope(first, first_report),)) == render_html(
        second_report, scopes=(HtmlScope(second, second_report),)
    )


def test_html_escapes_investigation_text_and_allows_only_https_references():
    value = snapshot()
    report = evaluate_snapshot(value)
    report.findings[0] = replace(
        report.findings[0], title='</script><svg onload="alert(1)">',
        references=["https://docs.aws.amazon.com/example", "javascript:alert(1)",
                    "//evil.example", "https://bad host/example", "https://example.com:443/x"],
    )
    html = render_html(report, scopes=(HtmlScope(value, report),))
    assert '<svg onload="alert(1)">' not in html
    assert 'href="https://docs.aws.amazon.com/example"' in html
    assert 'href="javascript:' not in html
    assert 'href="//evil.example"' not in html
    assert 'href="https://bad host' not in html
    assert 'href="https://example.com:443' not in html
    assert "innerHTML" not in html and "insertAdjacentHTML" not in html


def test_relationship_locator_enriches_collected_resource_without_fabricating_one():
    value = snapshot()
    collected = value.services["iam"].resources[0]
    value.services["iam"].resources[0] = replace(collected, resource_arn=None)
    report = evaluate_snapshot(value)
    view = build_html_view(report, (HtmlScope(value, report),))
    target = view["relationships"][0]["target"]
    worker = next(item for item in view["resources"] if item["resource_id"] == "worker")
    assert target["reference_kind"] == "collected"
    assert target["href"] == f"#{worker['anchor']}"
    assert worker["resource_arn"] == f"arn:aws:iam::{ACCOUNT}:role/worker"


def test_offline_html_cli_supplies_snapshot_investigation_context(monkeypatch, tmp_path):
    source = tmp_path / "snapshot.json"
    output = tmp_path / "report.html"
    write_snapshot(snapshot(), source)
    factory = Mock(side_effect=AssertionError("offline HTML created an AWS session"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    result = CliRunner().invoke(app, [
        "scan", str(source), "--output", "html", "--report-file", str(output),
    ])
    assert result.exit_code == 0
    html = output.read_text(encoding="utf-8")
    assert "AI-WORKLOAD-BROAD-EXECUTION-ROLE" in html
    assert "relationship-only reference" in html
    factory.assert_not_called()
