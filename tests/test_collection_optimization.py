from dataclasses import replace
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from awsherlock.regional import scan_regions
from awsherlock.snapshot import capture_snapshot
from awsherlock.evaluation import evaluate_snapshot
from test_s3 import context


@pytest.fixture(autouse=True)
def management_selectors(context):
    context.session.client.return_value.get_event_selectors.return_value = {
        "EventSelectors": [{"IncludeManagementEvents": True}]}


def trail(context):
    return {"Name": "synthetic", "TrailARN": f"arn:aws:cloudtrail:eu-west-1:{context.account_id}:trail/synthetic",
            "HomeRegion": "eu-west-1", "S3BucketName": "synthetic-logs",
            "IsMultiRegionTrail": True, "IncludeGlobalServiceEvents": True,
            "LogFileValidationEnabled": False, "IsOrganizationTrail": False}


@pytest.mark.parametrize("logging", [True, False])
def test_shadow_trail_reuse_preserves_findings_and_resets_each_scan(context, monkeypatch, logging):
    client = context.session.client.return_value
    client.describe_trails.return_value = {"trailList": [trail(context)]}
    client.get_trail_status.return_value = {"IsLogging": logging}
    target = replace(context, region="eu-west-1")
    # Establish the same fixture without sharing status across regional captures.
    with monkeypatch.context() as patch:
        patch.setattr("awsherlock.regional.capture_snapshot",
                      lambda ctx, services, **kwargs: capture_snapshot(replace(ctx, trail_status_cache=None,
                                                                               trail_selector_cache=None), services))
        before = scan_regions(target, ["cloudtrail"], ["eu-west-1", "eu-central-1"])
    assert client.get_trail_status.call_count == 2
    assert client.get_event_selectors.call_count == 2
    client.get_trail_status.reset_mock()
    client.get_event_selectors.reset_mock()
    after = scan_regions(target, ["cloudtrail"], ["eu-west-1", "eu-central-1"])
    assert client.get_trail_status.call_count == 1
    assert client.get_event_selectors.call_count == 1
    assert before.coverage == after.coverage
    assert [f.to_dict() for f in before.findings] == [f.to_dict() for f in after.findings]
    assert target.trail_status_cache is None
    scan_regions(target, ["cloudtrail"], ["eu-west-1", "eu-central-1"])
    assert client.get_trail_status.call_count == 2  # New scan, fresh read.


def test_failed_status_is_not_cached_and_earlier_failure_remains_visible(context):
    client = context.session.client.return_value
    client.describe_trails.return_value = {"trailList": [trail(context)]}
    client.get_trail_status.side_effect = [
        ClientError({"Error": {"Code": "AccessDenied", "Message": "hidden"}}, "GetTrailStatus"),
        {"IsLogging": True}]
    report = scan_regions(replace(context, region="eu-west-1"), ["cloudtrail"], ["eu-west-1", "eu-central-1"])
    assert report.incomplete and client.get_trail_status.call_count == 2
    assert report.coverage[0]["status"] == "PARTIAL"
    assert report.coverage[1]["status"] == "COMPLETE"


def test_status_cache_isolated_by_account_identity_and_home(context):
    from awsherlock.collectors.cloudtrail import collect_cloudtrail
    client = context.session.client.return_value
    client.describe_trails.return_value = {"trailList": [trail(context)]}
    client.get_trail_status.return_value = {"IsLogging": True}
    cache = {}
    target = replace(context, region="eu-west-1", trail_status_cache=cache)
    for variant in [target, replace(target, account_id="999999999999"),
                    replace(target, caller_arn=target.caller_arn + "Other")]:
        collect_cloudtrail(variant)
    assert client.get_trail_status.call_count == 3
    raw = trail(context)
    client.describe_trails.return_value = {"trailList": [{**raw, "HomeRegion": "eu-central-1"}]}
    collect_cloudtrail(target)
    assert client.get_trail_status.call_count == 4


@pytest.mark.parametrize("admin", [True, False])
def test_lambda_reuses_one_iam_client_but_reads_each_role(context, admin):
    client = context.session.client.return_value
    functions = [{"FunctionName": f"function-{i}", "FunctionArn": f"arn:aws:lambda:eu-west-1:{context.account_id}:function:function-{i}",
                  "Runtime": "python3.13", "Role": f"arn:aws:iam::{context.account_id}:role/Role{i}"}
                 for i in [1, 2]]
    policies = [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}] if admin else []
    def pages(operation):
        values = {"list_functions": {"Functions": functions},
                  "list_function_url_configs": {"FunctionUrlConfigs": []},
                  "list_attached_role_policies": {"AttachedPolicies": policies}}
        return Mock(paginate=Mock(return_value=[values[operation]]))
    client.get_paginator.side_effect = pages
    report = evaluate_snapshot(capture_snapshot(replace(context, region="eu-west-1"), ["lambda"]))
    assert not report.incomplete
    assert context.session.client.call_count == 2  # Lambda and one IAM client.
    assert client.get_paginator.call_count == 5
    assert len(report.findings) == (2 if admin else 0)
