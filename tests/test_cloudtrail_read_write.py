"""Management selectors distinguish read and write event inclusion."""

import pytest

from awsherlock.cloudtrail_facts import management_context
from awsherlock.collectors.common import InvalidResponse
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.reporting import render_html, render_json
from awsherlock.snapshot import SnapshotError, capture_snapshot, read_snapshot, write_snapshot
from test_audit import context
from test_cloudtrail_management import advanced
from test_s3 import aws_error


@pytest.mark.parametrize("response,read,write", [
    ({"EventSelectors": [{"ReadWriteType": "ReadOnly"}]}, True, False),
    ({"EventSelectors": [{"ReadWriteType": "WriteOnly"}]}, False, True),
    ({"EventSelectors": [{"ReadWriteType": "All"}]}, True, True),
    ({"EventSelectors": [{}]}, True, True),
    (advanced("Management", [{"Field": "readOnly", "Equals": ["true"]}]), True, False),
    (advanced("Management", [{"Field": "readOnly", "Equals": ["false"]}]), False, True),
    (advanced("Management"), True, True),
    (advanced("Management", [{"Field": "readOnly", "Equals": ["true", "false"]}]), True, True),
])
def test_basic_and_advanced_read_write_selection(context, response, read, write):
    context.session.client.return_value.get_event_selectors.return_value = response
    snapshot = capture_snapshot(context, ["cloudtrail"])
    report = evaluate_snapshot(snapshot)
    assert not report.incomplete
    trail = snapshot.services["cloudtrail"].resources[0]
    assert trail.data["management_event_types"] == {"read": read, "write": write}
    assert trail.data["management_events"] is True
    assert not any(f.id == "AWSH-CT-001" for f in report.findings)
    findings = [f for f in report.findings if f.id == "AWSH-CT-004"]
    assert bool(findings) is not (read and write)
    if findings:
        evidence = findings[0].evidence["management_events"]
        assert evidence["read_events"] is read and evidence["write_events"] is write
        assert "read_events" in render_json(report) and "write_events" in render_html(report)


@pytest.mark.parametrize("response", [
    {"EventSelectors": [{"ReadWriteType": "ReadOnly"}, {"ReadWriteType": "WriteOnly"}]},
    {"AdvancedEventSelectors": [
        *advanced("Management", [{"Field": "readOnly", "Equals": ["true"]}])["AdvancedEventSelectors"],
        *advanced("Management", [{"Field": "readOnly", "Equals": ["false"]}])["AdvancedEventSelectors"]]},
])
def test_multiple_selectors_union_read_and_write(context, response):
    context.session.client.return_value.get_event_selectors.return_value = response
    snapshot = capture_snapshot(context, ["cloudtrail"])
    report = evaluate_snapshot(snapshot)
    assert not report.incomplete
    assert snapshot.services["cloudtrail"].resources[0].data["management_event_types"] == {
        "read": True, "write": True}
    assert not any(f.id == "AWSH-CT-004" for f in report.findings)
    context.session.client.return_value.get_event_selectors.assert_called_once()


def test_source_exclusion_and_read_only_gap_share_finding(context):
    response = advanced("Management", [{"Field": "readOnly", "Equals": ["true"]},
                                       {"Field": "eventSource", "NotEquals": ["kms.amazonaws.com"]}])
    context.session.client.return_value.get_event_selectors.return_value = response
    report = evaluate_snapshot(capture_snapshot(context, ["cloudtrail"]))
    findings = [f for f in report.findings if f.id == "AWSH-CT-004"]
    assert len(findings) == 1
    assert findings[0].evidence["management_events"] == {
        "management_events": True, "excluded_sources": ["kms.amazonaws.com"],
        "read_events": True, "write_events": False}


def test_positive_old_snapshot_without_types_stays_incomplete(context, tmp_path):
    snapshot = capture_snapshot(context, ["cloudtrail"])
    trail = snapshot.services["cloudtrail"].resources[0]
    trail.data.pop("management_event_types")
    path = tmp_path / "old.json"
    write_snapshot(snapshot, path)
    report = evaluate_snapshot(read_snapshot(path))
    assert report.incomplete and report.coverage[0]["not_scanned"] == 1
    assert not any(f.id == "AWSH-CT-004" for f in report.findings)
    assert any(issue["operation"] == "RequiredFact" and
               "AWSH-CT-004 requires management_event_types" in issue["message"]
               for issue in report.coverage[0]["issues"])
    selected = evaluate_snapshot(read_snapshot(path), selected_checks=["AWSH-CT-001"])
    assert not any("management_event_types" in issue["message"] for issue in selected.coverage[0]["issues"])
    excluded = evaluate_snapshot(read_snapshot(path), selected_resources=["unmatched"])
    assert not any("management_event_types" in issue["message"] for issue in excluded.coverage[0]["issues"])


def test_negative_old_snapshot_still_reports_missing_management_events(context, tmp_path):
    context.session.client.return_value.get_event_selectors.return_value = {
        "EventSelectors": [{"IncludeManagementEvents": False}]}
    snapshot = capture_snapshot(context, ["cloudtrail"])
    trail = snapshot.services["cloudtrail"].resources[0]
    assert trail.data["management_event_types"] == {"read": False, "write": False}
    trail.data.pop("management_event_types")
    path = tmp_path / "old-negative.json"
    write_snapshot(snapshot, path)
    report = evaluate_snapshot(read_snapshot(path))
    assert not report.incomplete
    assert any(f.id == "AWSH-CT-004" for f in report.findings)


def test_denied_selector_read_has_no_new_context_or_false_pass(context):
    context.session.client.return_value.get_event_selectors.side_effect = aws_error("AccessDenied")
    snapshot = capture_snapshot(context, ["cloudtrail"])
    assert "management_event_types" not in snapshot.services["cloudtrail"].resources[0].data
    report = evaluate_snapshot(snapshot)
    assert report.incomplete and not any(f.id == "AWSH-CT-004" for f in report.findings)
    assert any("AWSH-CT-004 requires management_events" in issue["message"]
               for issue in report.coverage[0]["issues"])


@pytest.mark.parametrize("response", [
    {"EventSelectors": [{"ReadWriteType": []}]},
    {"EventSelectors": [{"ReadWriteType": "Both"}]},
    advanced("Management", [{"Field": "readOnly", "Equals": ["yes"]}]),
    advanced("Management", [{"Field": "readOnly", "NotEquals": ["true"]}]),
])
def test_malformed_selector_stays_unknown(response):
    with pytest.raises(InvalidResponse):
        management_context(response)


@pytest.mark.parametrize("value", [
    {"read": "true", "write": False}, {"read": True},
    {"read": True, "write": True, "extra": False}, {"read": False, "write": False},
])
def test_malformed_or_inconsistent_snapshot_types_are_rejected(context, tmp_path, value):
    snapshot = capture_snapshot(context, ["cloudtrail"])
    snapshot.services["cloudtrail"].resources[0].data["management_event_types"] = value
    with pytest.raises(SnapshotError):
        write_snapshot(snapshot, tmp_path / "invalid.json")
