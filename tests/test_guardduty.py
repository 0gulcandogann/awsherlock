"""GuardDuty detector posture with synthetic AWS responses only."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from awsherlock.collectors.guardduty import collect_guardduty
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.models import ScanMetadata
from awsherlock.reporting import render_html, render_json
from awsherlock.sarif import render_sarif
from awsherlock.scanner import parse_services
from awsherlock.snapshot import Snapshot, snapshot_from_dict


ACCOUNT = "123456789012"
REGION = "eu-west-1"


class DetectorPages:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self):
        yield from self.pages


class GuardDutyClient:
    def __init__(self, pages, statuses=None, *, denied_list=False):
        self.pages = pages
        self.statuses = statuses or {}
        self.denied_list = denied_list

    def get_paginator(self, operation):
        assert operation == "list_detectors"
        if self.denied_list:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "ListDetectors")
        return DetectorPages(self.pages)

    def get_detector(self, *, DetectorId):
        status = self.statuses[DetectorId]
        if status == "DENIED":
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetDetector")
        return {"Status": status}


def collect(client):
    def get_client(service, **options):
        assert service == "guardduty" and options == {"region_name": REGION}
        return client
    context = SimpleNamespace(account_id=ACCOUNT, region=REGION, client=get_client)
    return collect_guardduty(context)


def report_for(result):
    metadata = ScanMetadata(scan_id="test", started_at=datetime.now(timezone.utc),
                            account_id=ACCOUNT, region=REGION, version="test")
    snapshot = Snapshot(metadata, {"guardduty": result})
    return evaluate_snapshot(snapshot), snapshot


@pytest.mark.parametrize("pages,statuses", [
    ([{"DetectorIds": []}], {}),
    ([{"DetectorIds": ["detector-a"]}], {"detector-a": "DISABLED"}),
])
def test_no_enabled_detector_is_a_regional_finding(pages, statuses):
    report, snapshot = report_for(collect(GuardDutyClient(pages, statuses)))
    assert report.coverage[0]["status"] == "COMPLETE"
    assert [(f.id, f.region, f.evidence) for f in report.findings] == [
        ("AWSH-GD-001", REGION, {"enabled_detector_present": False})]
    assert [f.to_dict() for f in evaluate_snapshot(snapshot_from_dict(snapshot.to_dict())).findings] == [
        f.to_dict() for f in report.findings]
    for rendered in (render_json(report), render_html(report), render_sarif(report)):
        assert "AWSH-GD-001" in rendered


def test_paginated_enabled_detector_has_no_finding_and_is_opt_in():
    pages = [{"DetectorIds": ["detector-a"]}, {"DetectorIds": ["detector-b"]}]
    result = collect(GuardDutyClient(pages, {"detector-a": "DISABLED", "detector-b": "ENABLED"}))
    report, _ = report_for(result)
    assert result.resources[0].data == {"enabled_detector_present": True}
    assert not report.findings and report.coverage[0]["status"] == "COMPLETE"
    assert "guardduty" not in parse_services(None)
    assert parse_services("guardduty") == ["guardduty"]


def test_denied_listing_is_incomplete_not_a_no_detector_finding():
    report, _ = report_for(collect(GuardDutyClient([], denied_list=True)))
    assert not report.findings
    assert report.coverage[0]["status"] == "ACCESS_DENIED"
    assert any(issue["operation"] == "RequiredFact" for issue in report.coverage[0]["issues"])


def test_denied_or_malformed_detector_status_is_incomplete():
    for status in ("DENIED", "UNKNOWN"):
        report, _ = report_for(collect(GuardDutyClient(
            [{"DetectorIds": ["detector-a"]}], {"detector-a": status})))
        assert not report.findings
        assert report.coverage[0]["status"] == ("ACCESS_DENIED" if status == "DENIED" else "ERROR")
        assert any(issue["operation"] == "RequiredFact" for issue in report.coverage[0]["issues"])


def test_malformed_page_is_incomplete_and_duplicate_id_does_not_duplicate_status():
    for pages in ([{"BadKey": []}], [{"DetectorIds": ["detector-a", "detector-a"]}]):
        report, _ = report_for(collect(GuardDutyClient(pages, {"detector-a": "DISABLED"})))
        assert not report.findings and report.coverage[0]["status"] != "COMPLETE"


def test_observed_enabled_detector_retained_with_other_denied_status():
    result = collect(GuardDutyClient([{"DetectorIds": ["detector-a", "detector-b"]}],
                                     {"detector-a": "ENABLED", "detector-b": "DENIED"}))
    report, _ = report_for(result)
    assert result.resources[0].data == {"enabled_detector_present": True}
    assert not report.findings and report.coverage[0]["status"] == "PARTIAL"


def test_snapshot_rejects_truthy_string_and_missing_fact_is_incomplete():
    _, snapshot = report_for(collect(GuardDutyClient([{"DetectorIds": []}])))
    data = snapshot.to_dict()
    data["services"]["guardduty"]["resources"][0]["data"]["enabled_detector_present"] = "false"
    with pytest.raises(ValueError):
        snapshot_from_dict(data)
    data["services"]["guardduty"]["resources"][0]["data"] = {}
    report = evaluate_snapshot(snapshot_from_dict(data))
    assert not report.findings and report.coverage[0]["status"] == "NOT_SCANNED"
    assert any(issue["operation"] == "RequiredFact" for issue in report.coverage[0]["issues"])
