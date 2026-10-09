from dataclasses import replace
import json
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.organization import scan_organization
from awsherlock.regional import scan_regions
from awsherlock.selection import parse_resource_selection
from awsherlock.snapshot import capture_snapshot, write_snapshot
from awsherlock.reporting import render_html
from test_s3 import context
from test_snapshot import snapshot
from test_organization import account


def two_resources(snapshot):
    resource = snapshot.services["s3"].resources[0]
    snapshot.services["s3"].resources.append(replace(resource, resource_id="other-bucket", resource_arn="arn:aws:s3:::other-bucket"))
    snapshot.services["s3"].issues.clear()
    return snapshot


@pytest.mark.parametrize("selector", ["other-bucket", "arn:aws:s3:::other-bucket"])
def test_exact_id_or_arn_selection_keeps_coverage(snapshot, selector):
    snapshot = two_resources(snapshot)
    original = snapshot.to_dict()
    report = evaluate_snapshot(snapshot, selected_resources=[selector])
    assert [f.resource_id for f in report.findings] == ["other-bucket"]
    assert report.incomplete and report.coverage[0]["resources"] == 2
    assert report.coverage[0]["not_scanned"] == 9
    assert snapshot.to_dict() == original
    assert report.metadata["matched_resource_selectors"] == [selector]
    assert "Resource excluded by --resources" in render_html(report)


def test_unmatched_selector_and_denial_are_both_visible(snapshot):
    report = evaluate_snapshot(snapshot, selected_resources=["unknown"])
    assert report.coverage[0]["status"] == "ACCESS_DENIED"
    assert report.coverage[-1]["service"] == "selection"
    assert report.coverage[-1]["status"] == "NOT_SCANNED"
    assert report.coverage[-1]["issues"][0]["resource_id"] == "unknown"


def test_offline_cli_selection_never_authenticates(snapshot, tmp_path, monkeypatch):
    two_resources(snapshot)
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    factory = Mock(side_effect=AssertionError("Offline"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    result = CliRunner().invoke(app, ["scan", str(path), "--resources", "other-bucket", "--output", "json"])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["metadata"]["selected_resources"] == ["other-bucket"]
    assert [f["resource_id"] for f in data["findings"]] == ["other-bucket"]
    factory.assert_not_called()


@pytest.mark.parametrize("value", ["", "bucket,", "bucket*", "bucket?", "bad\nname"])
def test_invalid_resource_selectors_fail_before_auth(monkeypatch, value):
    factory = Mock()
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    assert CliRunner().invoke(app, ["scan", "--resources", value]).exit_code == 2
    factory.assert_not_called()


def test_live_selection_does_not_filter_saved_snapshot(context, tmp_path, monkeypatch):
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    path = tmp_path / "saved.json"
    result = CliRunner().invoke(app, ["scan", "--services", "s3", "--resources", "unknown", "--save-snapshot", str(path), "--output", "json"])
    assert result.exit_code == 1
    assert len(json.loads(path.read_text())["services"]["s3"]["resources"]) == 1
    assert context.session.client.return_value.get_bucket_logging.called


def test_match_in_later_region_is_not_unmatched(context, monkeypatch):
    from awsherlock.collectors.common import CollectionResult
    from awsherlock.models import Resource
    def capture(target, services, **kwargs):
        snapshot = capture_snapshot(context, ["s3"])
        resources = [Resource(service="ec2", resource_type="instance", account_id=context.account_id,
                              region=target.region, resource_id="i-selected" if target.region == "eu-west-1" else "i-other",
                              resource_arn=None, data={"metadata": {"endpoint": "enabled", "tokens": "required"}, "addresses": []})]
        return replace(snapshot, services={"ec2": CollectionResult(resources, [])})
    monkeypatch.setattr("awsherlock.regional.capture_snapshot", capture)
    report = scan_regions(context, ["ec2"], ["eu-central-1", "eu-west-1"], selected_resources=["i-selected"])
    assert report.metadata["matched_resource_selectors"] == ["i-selected"]
    assert len(report.coverage) == 2
    assert report.coverage[0]["status"] == "NOT_SCANNED"
    assert report.coverage[1]["status"] == "COMPLETE"


@pytest.mark.parametrize("regions", [None, ["eu-west-1", "eu-central-1"]])
def test_organization_unmatched_assessed_across_accounts(context, monkeypatch, regions):
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = [{"Accounts": [account(1), account(2)]}]
    monkeypatch.setattr("awsherlock.organization.create_scan_context", Mock(side_effect=lambda **kwargs:
                        replace(context, account_id=kwargs["role"].split(":")[4])))
    def capture(target, services, **kwargs):
        from awsherlock.collectors.common import CollectionResult
        from awsherlock.models import Resource, ScanMetadata
        from awsherlock.snapshot import Snapshot
        from datetime import datetime, timezone
        resource = Resource(service="s3", resource_type="bucket", account_id=target.account_id, region="us-east-1",
                            resource_id="selected" if target.account_id.endswith("2") else "other", resource_arn=None,
                            data={"public_access_block": None, "account_public_access_block": None})
        return Snapshot(ScanMetadata(scan_id="test", started_at=datetime.now(timezone.utc), account_id=target.account_id,
                                     region=None, version="test"), {"s3": CollectionResult([resource], [])})
    monkeypatch.setattr("awsherlock.organization.capture_snapshot", capture)
    monkeypatch.setattr("awsherlock.regional.capture_snapshot", capture)
    report = scan_organization(context, ["s3"], regions=regions, selected_resources=["selected"])
    assert len(report.coverage) == 2
    assert report.metadata["matched_resource_selectors"] == ["selected"]
    assert [f.account_id for f in report.findings] == ["000000000002"]


def test_parser_preserves_case_and_deduplicates():
    assert parse_resource_selection(" Bucket,Bucket,arn:aws:s3:::Bucket ") == ["Bucket", "arn:aws:s3:::Bucket"]
    assert parse_resource_selection(None) is None
