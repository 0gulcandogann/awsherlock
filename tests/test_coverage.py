import pytest
from awsherlock.collectors.common import CollectionIssue
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.reporting import render_console, render_json, render_html
from test_snapshot import snapshot


@pytest.mark.parametrize("facts,message,status", [
    ({}, "AccessDenied", "ACCESS_DENIED"),
    ({"public_access_block": None}, "AccessDenied", "PARTIAL"),
    ({}, "AWS request failed", "ERROR"),
    ({}, None, "NOT_SCANNED"),
])
def test_coverage_in_every_report(snapshot, facts, message, status, capsys):
    collection = snapshot.services["s3"]
    collection.resources[0].data.clear()
    collection.resources[0].data.update(facts)
    collection.issues = [CollectionIssue("test-bucket", "GetBucketLogging", message)] if message else []
    report = evaluate_snapshot(snapshot)
    assert report.coverage[0]["status"] == status
    assert report.incomplete
    assert report.coverage[0]["not_scanned"] == 5 - len(facts)
    assert status in render_json(report)
    assert status in render_html(report)
    render_console(report)
    assert status in capsys.readouterr().out


def test_empty_success_is_complete(snapshot):
    snapshot.services["s3"].resources.clear()
    snapshot.services["s3"].issues.clear()
    report = evaluate_snapshot(snapshot)
    assert not report.incomplete
    assert report.coverage[0]["status"] == "COMPLETE"
