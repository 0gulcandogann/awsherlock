"""EC2 keeps identified resources when one normalized fact is unavailable."""

import json
from unittest.mock import Mock

from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.collectors.common import CollectionIssue
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.snapshot import capture_snapshot, read_snapshot, write_snapshot
from test_ec2 import context
from test_s3 import aws_error


def pages(context, method):
    return context.session.client.return_value.get_paginator(method).paginate.return_value


def required(report):
    return [issue for issue in report.coverage[0]["issues"] if issue["operation"] == "RequiredFact"]


def test_invalid_security_group_ingress_preserves_resource_and_all_three_checks(context):
    pages(context, "describe_security_groups")[0]["SecurityGroups"][0]["IpPermissions"] = [
        {"IpProtocol": "tcp", "FromPort": 100, "ToPort": 1}
    ]
    snapshot = capture_snapshot(context, ["ec2"])
    group = next(resource for resource in snapshot.services["ec2"].resources if resource.resource_id == "sg-test")
    assert group.data == {}
    assert any(issue.operation == "describe_security_groups" and issue.resource_id == "sg-test"
               for issue in snapshot.services["ec2"].issues)
    report = evaluate_snapshot(snapshot)
    assert [issue["message"].split(" requires ")[0] for issue in required(report)] == [
        "AWSH-EC2-001", "AWSH-EC2-002", "AWSH-EC2-003"
    ]
    assert all("a related collection issue" in issue["message"] for issue in required(report))
    assert report.coverage[0]["status"] == "PARTIAL"
    assert any(finding.id == "AWSH-EC2-006" for finding in report.findings)


def test_invalid_instance_metadata_keeps_public_address_check(context):
    instance = pages(context, "describe_instances")[0]["Reservations"][0]["Instances"][0]
    instance["MetadataOptions"] = {"HttpEndpoint": "enabled", "HttpTokens": "invalid"}
    instance["PublicIpAddress"] = "8.8.8.8"
    snapshot = capture_snapshot(context, ["ec2"])
    resource = next(item for item in snapshot.services["ec2"].resources if item.resource_id == "i-test")
    assert resource.data == {"addresses": ["8.8.8.8"]}
    report = evaluate_snapshot(snapshot)
    assert [issue["message"] for issue in required(report)] == [
        "AWSH-EC2-004 requires metadata; a related collection issue is recorded separately."
    ]
    assert any(finding.id == "AWSH-EC2-005" for finding in report.findings)
    assert report.coverage[0]["not_scanned"] == 1


def test_invalid_instance_address_keeps_metadata_check(context):
    instance = pages(context, "describe_instances")[0]["Reservations"][0]["Instances"][0]
    instance["PublicIpAddress"] = "private-marker"
    snapshot = capture_snapshot(context, ["ec2"])
    resource = next(item for item in snapshot.services["ec2"].resources if item.resource_id == "i-test")
    assert resource.data["metadata"]["tokens"] == "required"
    assert "addresses" not in resource.data
    report = evaluate_snapshot(snapshot)
    assert [issue["message"] for issue in required(report)] == [
        "AWSH-EC2-005 requires addresses; a related collection issue is recorded separately."
    ]
    assert "private-marker" not in json.dumps(report.to_dict())
    assert report.coverage[0]["not_scanned"] == 1


def test_invalid_volume_preserves_other_volume_finding(context):
    pages(context, "describe_volumes")[0]["Volumes"][0]["Encrypted"] = "false"
    snapshot = capture_snapshot(context, ["ec2"])
    first = next(item for item in snapshot.services["ec2"].resources if item.resource_id == "vol-first")
    assert first.data == {}
    report = evaluate_snapshot(snapshot)
    assert [issue["message"] for issue in required(report)] == [
        "AWSH-EC2-006 requires encrypted; a related collection issue is recorded separately."
    ]
    assert any(finding.resource_id == "vol-second" and finding.id == "AWSH-EC2-006"
               for finding in report.findings)


def test_old_snapshot_does_not_claim_unrelated_failure(context, tmp_path):
    snapshot = capture_snapshot(context, ["ec2"])
    group = next(item for item in snapshot.services["ec2"].resources if item.resource_id == "sg-test")
    group.data.pop("ingress")
    snapshot.services["ec2"].issues.append(CollectionIssue("other-group", "describe_security_groups", "AccessDenied"))
    path = tmp_path / "old.json"
    write_snapshot(snapshot, path)
    issues = required(evaluate_snapshot(read_snapshot(path)))
    assert len(issues) == 3
    assert all("the fact is absent from this snapshot" in issue["message"] for issue in issues)


def test_selection_hides_required_fact_for_excluded_checks_and_resources(context):
    snapshot = capture_snapshot(context, ["ec2"])
    group = next(item for item in snapshot.services["ec2"].resources if item.resource_id == "sg-test")
    group.data.pop("ingress")
    by_check = evaluate_snapshot(snapshot, selected_checks=["AWSH-EC2-004"])
    assert not required(by_check)
    by_resource = evaluate_snapshot(snapshot, selected_resources=["vol-first"])
    assert not required(by_resource)


def test_denied_discovery_and_terminated_instance_do_not_invent_facts(context):
    client = context.session.client.return_value
    original = client.get_paginator.side_effect

    def paginator(method):
        if method == "describe_security_groups":
            raise aws_error("AccessDenied")
        return original(method)

    client.get_paginator.side_effect = paginator
    instance = pages(context, "describe_instances")[0]["Reservations"][0]["Instances"][0]
    instance["State"] = {"Name": "terminated"}
    report = evaluate_snapshot(capture_snapshot(context, ["ec2"]))
    assert all(item["resource_id"] not in {"sg-test", "i-test"} for item in required(report))
    assert report.coverage[0]["status"] == "PARTIAL"


def test_offline_json_console_html_show_safe_partial_coverage(context, monkeypatch, tmp_path):
    instance = pages(context, "describe_instances")[0]["Reservations"][0]["Instances"][0]
    instance["MetadataOptions"] = {"HttpEndpoint": "enabled", "HttpTokens": "invalid"}
    instance["UserData"] = "secret-marker"
    snapshot = capture_snapshot(context, ["ec2"])
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    factory = Mock(side_effect=AssertionError("offline replay must not authenticate"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(path), "--output", "json"])
    assert result.exit_code == 1
    issues = json.loads(result.stdout)["coverage"][0]["issues"]
    assert any(issue["operation"] == "RequiredFact" and
               issue["message"] == "AWSH-EC2-004 requires metadata; a related collection issue is recorded separately."
               for issue in issues)
    assert "secret-marker" not in result.stdout
    console = runner.invoke(app, ["scan", str(path), "--no-progress"])
    assert console.exit_code == 1 and "AWSH-EC2-004 requires metadata" in console.output
    html = tmp_path / "report.html"
    result = runner.invoke(app, ["scan", str(path), "--output", "html", "--report-file", str(html)])
    assert result.exit_code == 1 and "AWSH-EC2-004 requires metadata" in html.read_text()
    assert "secret-marker" not in html.read_text()
    factory.assert_not_called()
