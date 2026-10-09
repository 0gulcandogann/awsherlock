"""DynamoDB PITR posture with synthetic read-only API responses."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from awsherlock.collectors.dynamodb import collect_dynamodb
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.models import ScanMetadata
from awsherlock.reporting import render_console, render_html, render_json
from awsherlock.sarif import render_sarif
from awsherlock.scanner import parse_services
from awsherlock.snapshot import Snapshot, snapshot_from_dict


ACCOUNT = "123456789012"
REGION = "eu-west-1"


class Pages:
    def __init__(self, pages, denied=False):
        self.pages = pages
        self.denied = denied

    def paginate(self):
        for page in self.pages:
            if self.denied and page is None:
                raise ClientError({"Error": {"Code": "AccessDenied"}}, "ListTables")
            yield page


class DynamoClient:
    def __init__(self, pages, statuses=None):
        self.pages = pages
        self.statuses = statuses or {}

    def get_paginator(self, operation):
        assert operation == "list_tables"
        return Pages(self.pages, denied=True)

    def describe_continuous_backups(self, *, TableName):
        status = self.statuses[TableName]
        if status == "DENIED":
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "DescribeContinuousBackups")
        if status == "MALFORMED":
            return {"ContinuousBackupsDescription": {"ContinuousBackupsStatus": "ENABLED"}}
        return {"ContinuousBackupsDescription": {
            "ContinuousBackupsStatus": "ENABLED",
            "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": status}}}


def collect(client):
    def get_client(service, **options):
        assert service == "dynamodb" and options == {"region_name": REGION}
        return client
    context = SimpleNamespace(account_id=ACCOUNT, partition="aws", region=REGION,
                              client=get_client)
    return collect_dynamodb(context)


def report_for(result):
    metadata = ScanMetadata(scan_id="test", started_at=datetime.now(timezone.utc),
                            account_id=ACCOUNT, region=REGION, version="test")
    snapshot = Snapshot(metadata, {"dynamodb": result})
    return evaluate_snapshot(snapshot), snapshot


def test_secure_and_insecure_tables_paginate_and_replay(capsys):
    result = collect(DynamoClient([{"TableNames": ["private-table"]},
                                   {"TableNames": ["unprotected-table"]}],
                                  {"private-table": "ENABLED", "unprotected-table": "DISABLED"}))
    report, snapshot = report_for(result)
    assert not result.issues and report.coverage[0]["status"] == "COMPLETE"
    assert [(f.id, f.resource_id, f.evidence) for f in report.findings] == [
        ("AWSH-DDB-001", "table:unprotected-table", {"pitr_enabled": False})]
    assert result.resources[0].resource_arn == f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/private-table"
    assert [f.to_dict() for f in evaluate_snapshot(snapshot_from_dict(snapshot.to_dict())).findings] == [
        f.to_dict() for f in report.findings]
    for rendered in (render_json(report), render_html(report), render_sarif(report)):
        assert "AWSH-DDB-001" in rendered
        assert "unprotected-table" in rendered
    render_console(report)
    assert "AWSH-DDB-001" in capsys.readouterr().out
    assert "dynamodb" not in parse_services(None)
    assert parse_services("dynamodb") == ["dynamodb"]


def test_empty_successful_listing_is_complete():
    report, _ = report_for(collect(DynamoClient([{"TableNames": []}])))
    assert report.coverage[0]["status"] == "COMPLETE" and not report.findings


def test_denied_detail_is_incomplete_and_other_table_still_evaluates():
    result = collect(DynamoClient([{"TableNames": ["unknown-table", "bad-table"]}],
                                  {"unknown-table": "DENIED", "bad-table": "DISABLED"}))
    report, _ = report_for(result)
    assert {f.resource_id for f in report.findings} == {"table:bad-table"}
    assert report.coverage[0]["status"] == "PARTIAL"
    assert any(issue["operation"] == "RequiredFact" and issue["resource_id"] == "table:unknown-table"
               for issue in report.coverage[0]["issues"])


@pytest.mark.parametrize("status", ["MALFORMED", "ENABLING", None])
def test_missing_or_unknown_status_never_passes(status):
    result = collect(DynamoClient([{"TableNames": ["unknown-table"]}], {"unknown-table": status}))
    report, _ = report_for(result)
    assert not report.findings and report.coverage[0]["status"] != "COMPLETE"
    assert any(issue["operation"] == "DescribeContinuousBackups" for issue in report.coverage[0]["issues"])


def test_partial_listing_keeps_observed_finding_but_not_complete():
    result = collect(DynamoClient([{"TableNames": ["bad-table"]}, None], {"bad-table": "DISABLED"}))
    report, _ = report_for(result)
    assert [f.id for f in report.findings] == ["AWSH-DDB-001"]
    assert report.coverage[0]["status"] == "PARTIAL"
    assert any(issue["operation"] == "ListTables" and issue["message"] == "AccessDenied"
               for issue in report.coverage[0]["issues"])


def test_malformed_and_duplicate_names_are_issues_without_duplicate_findings():
    result = collect(DynamoClient([{"TableNames": ["bad-table", "bad-table", "x", "slash/name"]}],
                                  {"bad-table": "DISABLED"}))
    report, _ = report_for(result)
    assert [f.id for f in report.findings] == ["AWSH-DDB-001"]
    assert report.coverage[0]["status"] == "PARTIAL"
    assert sum(issue["operation"] == "ListTables" for issue in report.coverage[0]["issues"]) == 3


def test_old_or_invalid_snapshot_fact_is_not_a_pass():
    _, snapshot = report_for(collect(DynamoClient([{"TableNames": ["one-table"]}],
                                                  {"one-table": "ENABLED"})))
    raw = snapshot.to_dict()
    raw["services"]["dynamodb"]["resources"][0]["data"]["pitr_enabled"] = "false"
    with pytest.raises(ValueError):
        snapshot_from_dict(raw)
    raw["services"]["dynamodb"]["resources"][0]["data"] = {}
    replay = evaluate_snapshot(snapshot_from_dict(raw))
    assert not replay.findings and replay.coverage[0]["status"] == "NOT_SCANNED"
    assert any(issue["operation"] == "RequiredFact" for issue in replay.coverage[0]["issues"])
