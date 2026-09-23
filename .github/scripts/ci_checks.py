"""Small installed-package scanner checks using synthetic AWS responses only."""

from datetime import datetime, timezone
from unittest.mock import Mock

from botocore.exceptions import ClientError

from awsherlock.aws.context import ScanContext
from awsherlock.collectors.ec2 import collect_ec2
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.models import ScanMetadata
from awsherlock.snapshot import Snapshot


ACCOUNT = "123456789012"
REGION = "eu-west-1"


def mocked_scan(volume_response):
    client = Mock()

    def paginator(method):
        pages = {
            "describe_security_groups": [{"SecurityGroups": []}],
            "describe_instances": [{"Reservations": []}],
            "describe_volumes": [volume_response] if isinstance(volume_response, dict) else volume_response,
        }[method]
        result = Mock()
        if isinstance(pages, Exception):
            result.paginate.side_effect = pages
        else:
            result.paginate.return_value = pages
        return result

    client.get_paginator.side_effect = paginator
    session = Mock()
    session.client.return_value = client
    context = ScanContext(account_id=ACCOUNT, caller_arn=f"arn:aws:iam::{ACCOUNT}:role/CI",
                          partition="aws", profile=None, region=REGION, session=session)
    metadata = ScanMetadata(scan_id="ci-synthetic", started_at=datetime(2026, 9, 23, tzinfo=timezone.utc),
                            account_id=ACCOUNT, region=REGION, version="ci")
    snapshot = Snapshot(metadata, {"ec2": collect_ec2(context)})
    session.client.assert_called_once_with("ec2", region_name=REGION)
    return evaluate_snapshot(snapshot)


def main():
    insecure = mocked_scan({"Volumes": [{"VolumeId": "vol-ci", "Encrypted": False}]})
    secure = mocked_scan({"Volumes": [{"VolumeId": "vol-ci", "Encrypted": True}]})
    denied = mocked_scan(ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}},
                                     "DescribeVolumes"))
    assert [finding.id for finding in insecure.findings] == ["AWSH-EC2-006"]
    assert not secure.findings and not secure.incomplete
    assert not denied.findings and denied.incomplete
    assert denied.coverage[0]["status"] == "ACCESS_DENIED"
    assert any(issue["message"].startswith("AccessDenied") for issue in denied.coverage[0]["issues"])
    print("PASS: synthetic EC2 insecure, secure, AccessDenied and coverage checks")


if __name__ == "__main__":
    main()
