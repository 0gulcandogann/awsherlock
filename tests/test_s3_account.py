from dataclasses import replace

import pytest

from awsherlock.collectors.s3 import collect_s3
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.rules.s3 import S3PublicAccessRule
from awsherlock.snapshot import capture_snapshot, read_snapshot, write_snapshot
from test_s3 import context, FLAGS, aws_error


@pytest.mark.parametrize("account_flags", [FLAGS, dict.fromkeys(FLAGS, False), None])
def test_account_context_and_combined_safeguards(context, account_flags):
    account = context.client("s3control")
    if account_flags is None:
        account.get_public_access_block.side_effect = aws_error("NoSuchPublicAccessBlockConfiguration")
    else:
        account.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": account_flags}
    context.session.client.return_value.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": dict.fromkeys(FLAGS, False)}
    report = evaluate_snapshot(capture_snapshot(context, ["s3"]))
    assert not report.incomplete
    finding = next(f for f in report.findings if f.id == "AWSH-S3-001")
    assert finding.evidence["account_context"] == "known"
    assert finding.evidence["combined_public_access_block"] == (account_flags or dict.fromkeys(FLAGS, False))


def test_account_read_once_across_pages_and_fresh_account(context):
    client = context.session.client.return_value
    client.get_paginator.return_value.paginate.return_value = [
        {"Buckets": [{"Name": "first"}]}, {"Buckets": [{"Name": "second"}]}]
    account = context.client("s3control")
    assert len(collect_s3(context).resources) == 2
    account.get_public_access_block.assert_called_once_with(AccountId=context.account_id)
    collect_s3(replace(context, account_id="999999999999"))
    assert account.get_public_access_block.call_count == 2
    assert account.get_public_access_block.call_args.kwargs == {"AccountId": "999999999999"}


@pytest.mark.parametrize("bad", ["denied", {}, {"PublicAccessBlockConfiguration": {**FLAGS, "BlockPublicAcls": "true"}}])
def test_unknown_account_context_keeps_valid_bucket_facts_and_partial(context, bad):
    account = context.client("s3control")
    if bad == "denied":
        account.get_public_access_block.side_effect = aws_error("AccessDenied")
    else:
        account.get_public_access_block.return_value = bad
    snapshot = capture_snapshot(context, ["s3"])
    report = evaluate_snapshot(snapshot)
    assert report.incomplete and report.coverage[0]["evaluated"] == 5
    assert "account_public_access_block" not in snapshot.services["s3"].resources[0].data
    assert "secret-marker" not in str(report.to_dict())


def test_old_snapshot_context_is_unknown(context, tmp_path):
    snapshot = capture_snapshot(context, ["s3"])
    snapshot.services["s3"].resources[0].data.pop("account_public_access_block")
    path = tmp_path / "old.json"
    write_snapshot(snapshot, path)
    report = evaluate_snapshot(read_snapshot(path))
    assert report.incomplete
    assert any(i["operation"] == "AccountPublicAccessContext" for i in report.coverage[0]["issues"])


def test_secure_bucket_has_no_safeguard_finding(context):
    assert S3PublicAccessRule().evaluate(collect_s3(context).resources[0]) == []
