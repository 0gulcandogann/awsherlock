from dataclasses import replace
import json

import pytest

from awsherlock.cloudtrail_facts import management_context, management_events
from awsherlock.collectors.common import InvalidResponse
from awsherlock.collectors.cloudtrail import collect_cloudtrail
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.reporting import render_console, render_html, render_json
from awsherlock.rules.audit import CLOUDTRAIL_RULES
from awsherlock.snapshot import capture_snapshot, read_snapshot, write_snapshot
from test_audit import context
from test_s3 import aws_error


def advanced(category, extra=None):
    return {"AdvancedEventSelectors": [{"FieldSelectors": [
        {"Field": "eventCategory", "Equals": [category]}, *(extra or [])]}]}


@pytest.mark.parametrize("response,expected", [
    ({"EventSelectors": [{"IncludeManagementEvents": True}]}, True),
    ({"EventSelectors": [{}]}, True),
    ({"EventSelectors": [{"IncludeManagementEvents": False}]}, False),
    ({"EventSelectors": [{"IncludeManagementEvents": False}, {"IncludeManagementEvents": True}]}, True),
    (advanced("Management"), True), (advanced("Data"), False),
    (advanced("Data", [{"Field": "resources.type", "Equals": ["AWS::S3::Object"]}]), False),
    (advanced("Management", [{"Field": "readOnly", "Equals": ["true"]}]), True),
])
def test_management_selector_facts(response, expected):
    assert management_events(response) is expected


@pytest.mark.parametrize("response", [
    {}, None, {"EventSelectors": []}, {"EventSelectors": "secret"}, {"EventSelectors": [None]},
    {"EventSelectors": [{"IncludeManagementEvents": "false"}]},
    {"EventSelectors": [{"ReadWriteType": "invalid"}]},
    {"AdvancedEventSelectors": [{"FieldSelectors": []}]},
    advanced("Management", [{"Field": "eventName", "Equals": ["DeleteBucket"]}]),
    advanced("Management", [{"Field": "readOnly", "Equals": ["invalid"]}]),
    advanced("Management", [{"Field": "readOnly", "Equals": ["true"]},
                            {"Field": "readOnly", "Equals": ["false"]}]),
    {"AdvancedEventSelectors": [{"FieldSelectors": [{"Field": "eventCategory", "NotEquals": ["Management"]}]}]},
    {"EventSelectors": [{}], **advanced("Management")},
])
def test_unknown_selectors_never_become_pass(response):
    with pytest.raises(InvalidResponse):
        management_events(response)


@pytest.mark.parametrize("enabled", [True, False])
def test_live_secure_insecure_rule_and_offline_replay(context, tmp_path, enabled):
    context.session.client.return_value.get_event_selectors.return_value = {
        "EventSelectors": [{"IncludeManagementEvents": enabled}]}
    snapshot = capture_snapshot(context, ["cloudtrail"])
    report = evaluate_snapshot(snapshot)
    assert not report.incomplete
    assert any(f.id == "AWSH-CT-004" for f in report.findings) is not enabled
    assert any(f.id == "AWSH-CT-001" for f in report.findings) is not enabled
    assert snapshot.services["cloudtrail"].resources[0].data["management_events"] is enabled
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    assert evaluate_snapshot(read_snapshot(path)).to_dict() == report.to_dict()


def test_get_selectors_denied_is_partial_and_no_selector_pass(context):
    context.session.client.return_value.get_event_selectors.side_effect = aws_error("AccessDenied")
    snapshot = capture_snapshot(context, ["cloudtrail"])
    report = evaluate_snapshot(snapshot)
    assert report.incomplete and report.coverage[0]["status"] == "PARTIAL"
    assert report.coverage[0]["not_scanned"] == 2  # Usability and management selectors.
    assert "usable_trail" not in snapshot.services["cloudtrail"].resources[-1].data
    assert "management_events" not in snapshot.services["cloudtrail"].resources[0].data
    missing = [issue for issue in report.coverage[0]["issues"] if issue["operation"] == "RequiredFact"]
    assert any("AWSH-CT-004 requires management_events" in issue["message"] and
               "related collection issue" in issue["message"] for issue in missing)
    assert any("AWSH-CT-001 requires usable_trail" in issue["message"] for issue in missing)
    assert "secret-marker" not in json.dumps(report.to_dict())


def test_foreign_single_region_trail_does_not_cover_scanned_region(context):
    client = context.session.client.return_value
    client.describe_trails.return_value["trailList"][0]["IsMultiRegionTrail"] = False
    result = collect_cloudtrail(context)
    assert result.resources[-1].data["usable_trail"] is False


def test_old_snapshot_missing_selector_fact_is_readable_but_incomplete(context, tmp_path, capsys):
    snapshot = capture_snapshot(context, ["cloudtrail"])
    snapshot.services["cloudtrail"].resources[0].data.pop("management_events")
    path = tmp_path / "old.json"
    write_snapshot(snapshot, path)
    report = evaluate_snapshot(read_snapshot(path))
    assert report.incomplete and report.coverage[0]["not_scanned"] == 1
    missing = [issue for issue in report.coverage[0]["issues"] if issue["operation"] == "RequiredFact"]
    assert len(missing) == 1
    assert missing[0]["message"] == "AWSH-CT-004 requires management_events; the fact is absent from this snapshot."
    assert missing[0]["resource_id"] == snapshot.services["cloudtrail"].resources[0].resource_id
    assert "AWSH-CT-004 requires management_events" in render_json(report)
    assert "AWSH-CT-004 requires management_events" in render_html(report)
    render_console(report)
    assert "NOT_SCANNED" in capsys.readouterr().err


def test_management_fact_rejects_truthy_string_in_snapshot(context, tmp_path):
    from awsherlock.snapshot import SnapshotError
    snapshot = capture_snapshot(context, ["cloudtrail"])
    snapshot.services["cloudtrail"].resources[0].data["management_events"] = "true"
    with pytest.raises(SnapshotError):
        write_snapshot(snapshot, tmp_path / "bad.json")


@pytest.mark.parametrize("sources", [["kms.amazonaws.com"], ["rdsdata.amazonaws.com"],
                                     ["kms.amazonaws.com", "rdsdata.amazonaws.com"]])
def test_documented_exclusions_make_specific_finding_and_replay(context, tmp_path, sources):
    response = advanced("Management", [{"Field": "eventSource", "NotEquals": sources}])
    context.session.client.return_value.get_event_selectors.return_value = response
    snapshot = capture_snapshot(context, ["cloudtrail"])
    report = evaluate_snapshot(snapshot)
    assert not report.incomplete
    assert not any(f.id == "AWSH-CT-001" for f in report.findings)
    finding = next(f for f in report.findings if f.id == "AWSH-CT-004")
    assert finding.evidence["management_events"]["excluded_sources"] == sorted(sources)
    path = tmp_path / "exclusions.json"
    write_snapshot(snapshot, path)
    assert evaluate_snapshot(read_snapshot(path)).to_dict() == report.to_dict()


def test_multiple_selectors_do_not_overstate_common_exclusion():
    response = advanced("Management", [{"Field": "eventSource", "NotEquals": ["kms.amazonaws.com"]}])
    response["AdvancedEventSelectors"].extend(advanced("Management")["AdvancedEventSelectors"])
    assert management_context(response) == {"management_events": True, "management_excluded_sources": [],
                                            "management_event_types": {"read": True, "write": True}}


@pytest.mark.parametrize("field", [
    {"Field": "eventSource", "Equals": ["kms.amazonaws.com"]},
    {"Field": "eventSource", "NotEquals": ["unknown.amazonaws.com"]},
    {"Field": "eventSource", "NotEquals": []},
    {"Field": "eventSource", "NotEquals": ["kms.amazonaws.com"], "Equals": ["kms.amazonaws.com"]},
])
def test_unsupported_source_shapes_stay_unknown(field):
    with pytest.raises(InvalidResponse):
        management_context(advanced("Management", [field]))


def test_basic_management_source_exclusion():
    assert management_context({"EventSelectors": [{"ExcludeManagementEventSources": ["kms.amazonaws.com"]}]}) == {
        "management_events": True, "management_excluded_sources": ["kms.amazonaws.com"],
        "management_event_types": {"read": True, "write": True}}


def test_old_snapshot_without_source_context_does_not_pass(context):
    snapshot = capture_snapshot(context, ["cloudtrail"])
    snapshot.services["cloudtrail"].resources[0].data.pop("management_excluded_sources")
    report = evaluate_snapshot(snapshot)
    assert report.incomplete and report.coverage[0]["not_scanned"] == 1
    assert not any(f.id == "AWSH-CT-004" for f in report.findings)
    issues = report.coverage[0]["issues"]
    assert any(issue["operation"] == "RequiredFact" and
               "AWSH-CT-004 requires management_excluded_sources" in issue["message"] for issue in issues)
    assert not any(issue["operation"] == "RuleEvaluation" for issue in issues)


def test_missing_fact_explanations_respect_check_and_resource_selection(context):
    snapshot = capture_snapshot(context, ["cloudtrail"])
    snapshot.services["cloudtrail"].resources[0].data.pop("management_events")
    check_report = evaluate_snapshot(snapshot, selected_checks=["AWSH-CT-001"])
    assert not any(issue["operation"] == "RequiredFact" for issue in check_report.coverage[0]["issues"])
    resource_report = evaluate_snapshot(snapshot, selected_resources=["unmatched"])
    assert not any(issue["operation"] == "RequiredFact" for issue in resource_report.coverage[0]["issues"])


def test_only_missing_cloudtrail_facts_stay_not_scanned(context):
    snapshot = capture_snapshot(context, ["cloudtrail"])
    for resource in snapshot.services["cloudtrail"].resources:
        resource.data.clear()
    report = evaluate_snapshot(snapshot)
    assert report.coverage[0]["status"] == "NOT_SCANNED"
    assert report.coverage[0]["not_scanned"] == 4
    assert not report.findings
