"""Identity, timeout, regional and replay controls use synthetic AWS responses."""

from dataclasses import replace
from io import StringIO
import json
from unittest.mock import Mock

import pytest
from botocore.config import Config
from botocore.exceptions import ReadTimeoutError
from rich.console import Console
from typer.testing import CliRunner

from awsherlock.aws.session import SessionError, create_scan_context
from awsherlock.collectors.common import CollectionIssue, CollectionResult
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.models import Resource
from awsherlock.organization import scan_organization
from awsherlock.regional import parse_regions, scan_regions
from awsherlock.reporting import render_console, render_html
from awsherlock.scanner import SERVICES, service_components
from awsherlock.snapshot import capture_snapshot, read_snapshot, snapshot_saver, write_snapshot
from awsherlock.cli import app
from awsherlock.terminal import COLOR_MODE
from test_s3 import context
from test_snapshot import snapshot
from test_session import session_factory
from test_assume_role import sessions, ROLE
from test_cli_options import no_aws


def test_wrong_live_account_stops_before_collection(session_factory, monkeypatch):
    collect = Mock(side_effect=AssertionError("Must not collect"))
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", collect)
    result = CliRunner().invoke(app, ["scan", "--expect-account", "999999999999", "--no-progress"])
    assert result.exit_code == 1 and "does not match" in result.stderr
    collect.assert_not_called()
    session_factory.return_value.get_credentials.assert_not_called()


def test_expected_role_account_mismatch_fails_before_aws(sessions):
    factory, _, _ = sessions
    with pytest.raises(SessionError, match="expected AWS account"):
        create_scan_context(role=ROLE, expect_account="111111111111")
    factory.assert_not_called()


@pytest.mark.parametrize("match", [False, True])
def test_offline_account_guard_and_stats(snapshot, tmp_path, match):
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    expected = snapshot.metadata.account_id if match else "999999999999"
    result = CliRunner().invoke(app, ["scan", str(path), "--expect-account", expected,
                                    "--stats", "--output", "json", "--no-progress"])
    assert result.exit_code == 1
    if match:
        assert json.loads(result.stdout) == evaluate_snapshot(snapshot).to_dict()
        assert "Stats:" in result.stderr and "resources" in result.stderr
    else:
        assert "does not match" in result.stderr and result.stdout == ""


def test_request_config_reaches_source_and_assumed_sts(sessions):
    factory, source, target = sessions
    config = Config(connect_timeout=2.5, read_timeout=7)
    context = create_scan_context(role=ROLE, client_config=config, expect_account="999999999999")
    source.client.assert_called_with("sts", config=config)
    target.client.assert_called_with("sts", config=config)
    assert context.client_config is config
    context.client("ec2", region_name="eu-west-1")
    target.client.assert_called_with("ec2", region_name="eu-west-1", config=config)


@pytest.mark.parametrize("service", SERVICES)
def test_timeout_collection_is_incomplete_and_configured(context, service):
    config = Config(connect_timeout=2, read_timeout=3)
    target = replace(context, region="eu-west-1", client_config=config)
    target.session.client.side_effect = ReadTimeoutError(endpoint_url="https://private-marker.invalid")
    report = evaluate_snapshot(capture_snapshot(target, [service]))
    assert report.incomplete and report.coverage[0]["status"] != "COMPLETE"
    assert target.session.client.call_args.kwargs["config"] is config
    assert "private-marker" not in json.dumps(report.to_dict())


def install_regional_collectors(monkeypatch, calls, denied=False):
    def components(service):
        _, rules = service_components(service)
        def collect(target):
            calls.append((service, target.region, target.session))
            if service == "ec2":
                if denied and target.region == "eu-central-1":
                    return CollectionResult([], [CollectionIssue(None, "DescribeVolumes", "AccessDenied")])
                resource = Resource(service="ec2", resource_type="volume", account_id=target.account_id,
                                    region=target.region, resource_id="same-local-volume-id", resource_arn=None,
                                    data={"encrypted": False})
                return CollectionResult([resource], [])
            return CollectionResult([], [])
        return collect, rules
    monkeypatch.setattr("awsherlock.snapshot.service_components", components)


@pytest.mark.parametrize("denied", [False, True])
def test_regions_deduplicate_globals_and_preserve_region_failures(context, monkeypatch, tmp_path, denied):
    calls, events = [], []
    install_regional_collectors(monkeypatch, calls, denied)
    destination = tmp_path / "bundle"
    target = replace(context, region="eu-west-1")
    report = scan_regions(target, ["iam", "s3", "ec2"], ["eu-west-1", "eu-central-1"],
                          progress=lambda *event: events.append(event),
                          snapshot_sink=snapshot_saver(destination, bundle=True))
    assert [call[0] for call in calls] == ["iam", "s3", "ec2", "ec2"]
    assert all(call[2] is context.session for call in calls)
    assert report.incomplete == denied
    assert len(report.findings) == (1 if denied else 2)
    coverage = report.coverage
    assert [entry["region"] for entry in coverage] == [None, None, "eu-west-1", "eu-central-1"]
    assert coverage[0]["scope"] == "global" and coverage[1]["scope"] == "bucket"
    assert coverage[-1]["status"] == ("ACCESS_DENIED" if denied else "COMPLETE")
    percentages = [completed / total for _, completed, total in events]
    assert percentages == sorted(percentages) and percentages[-1] == 1
    snapshots = [read_snapshot(path) for path in destination.glob("*.json")]
    assert len(snapshots) == 3
    assert sum(len(evaluate_snapshot(snapshot).findings) for snapshot in snapshots) == len(report.findings)
    html = render_html(report)
    assert "Region / Scope" in html and "eu-west-1" in html and "eu-central-1" in html
    stdout, stderr = StringIO(), StringIO()
    monkeypatch.setattr("awsherlock.reporting.Console", lambda **kwargs: Console(
        file=stderr if kwargs.get("stderr") else stdout, width=200, color_system=None))
    render_console(report)
    assert "Region / Scope" in stdout.getvalue() and "eu-central-1" in stdout.getvalue()
    if denied:
        assert "eu-central-1" in stderr.getvalue() and "AccessDenied" in stderr.getvalue()


def test_organization_regions_and_timeouts_keep_failed_accounts(context, monkeypatch):
    from test_organization import account
    source = replace(context, region="eu-west-1", client_config=Config(read_timeout=3))
    source.session.client.return_value.get_paginator.return_value.paginate.return_value = [
        {"Accounts": [account(1), account(2), account(3, "SUSPENDED")]}]
    target = replace(source, account_id="000000000001")
    factory = Mock(side_effect=[target, SessionError("AccessDenied: AWS AssumeRole request was denied.")])
    monkeypatch.setattr("awsherlock.organization.create_scan_context", factory)
    calls = []
    install_regional_collectors(monkeypatch, calls)
    report = scan_organization(source, ["iam", "ec2"], regions=["eu-west-1", "eu-central-1"])
    assert report.incomplete and len(report.coverage) == 9
    assert report.metadata["regions"] == ["eu-west-1", "eu-central-1"]
    assert [account["scan_status"] for account in report.metadata["accounts"]] == ["COMPLETE", "ACCESS_DENIED", "NOT_SCANNED"]
    assert all(call.kwargs["client_config"] is source.client_config for call in factory.call_args_list)
    source.session.client.assert_called_with("organizations", config=source.client_config)
    assert [entry["region"] for entry in report.coverage[-3:]] == [None, "eu-west-1", "eu-central-1"]


@pytest.mark.parametrize("args", [
    ["--region", "eu-west-1", "--regions", "eu-central-1"],
    ["--regions", ""], ["--regions", "eu-west-1,"], ["--regions", "bad\x1b[2J"],
    ["--expect-account", "123"], ["--expect-account", "123456789012\n"],
    ["--timeout", "0"], ["--timeout", "-1"], ["--timeout", "nan"],
    ["--timeout", "inf"], ["--read-timeout", "3601"],
    ["--timeout", "3", "--connect-timeout", "1"], ["--color", "invalid"],
])
def test_invalid_controls_fail_before_aws(args, no_aws):
    result = CliRunner().invoke(app, ["scan", *args])
    assert result.exit_code == 2
    no_aws.assert_not_called()


def test_regions_parser_deduplicates_preserving_order():
    assert parse_regions("eu-west-1,eu-central-1,eu-west-1") == ["eu-west-1", "eu-central-1"]


def test_save_snapshot_and_json_preserve_partial_exit(snapshot, context, monkeypatch, tmp_path):
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    collect = Mock(return_value=snapshot)
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", collect)
    destination = tmp_path / "saved.json"
    result = CliRunner().invoke(app, ["scan", "--save-snapshot", str(destination),
                                    "--timeout", "4", "--output", "json", "--no-progress"])
    assert result.exit_code == 1
    assert json.loads(result.stdout) == evaluate_snapshot(snapshot).to_dict()
    assert read_snapshot(destination).to_dict() == snapshot.to_dict()
    config = __import__("awsherlock.cli", fromlist=["create_scan_context"]).create_scan_context.call_args.kwargs["client_config"]
    assert config.connect_timeout == config.read_timeout == 4
    second = CliRunner().invoke(app, ["scan", "--save-snapshot", str(destination)])
    assert second.exit_code == 2 and collect.call_count == 1


def test_color_is_scoped_and_never_keeps_json_clean(snapshot, tmp_path):
    from typer import rich_utils
    prior = (rich_utils.FORCE_TERMINAL, rich_utils.COLOR_SYSTEM)
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    result = CliRunner().invoke(app, ["scan", str(path), "--color", "never", "--output", "json", "--no-progress"])
    assert result.exit_code == 1 and "\x1b" not in result.stdout
    assert json.loads(result.stdout) == evaluate_snapshot(snapshot).to_dict()
    assert COLOR_MODE.get() == "auto"
    assert (rich_utils.FORCE_TERMINAL, rich_utils.COLOR_SYSTEM) == prior
    help_result = CliRunner().invoke(app, ["--color", "never", "--help"])
    assert help_result.exit_code == 0 and "\x1b" not in help_result.stdout


def test_multi_region_cli_json_and_snapshot_bundle(context, monkeypatch, tmp_path):
    calls = []
    install_regional_collectors(monkeypatch, calls, denied=True)
    factory = Mock(return_value=replace(context, region="eu-west-1"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    destination = tmp_path / "facts"
    result = CliRunner().invoke(app, ["scan", "--regions", "eu-west-1,eu-central-1,eu-west-1",
                                    "--services", "iam,s3,ec2", "--save-snapshot", str(destination),
                                    "--stats", "--output", "json", "--no-progress"])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["metadata"]["regions"] == ["eu-west-1", "eu-central-1"]
    assert data["summary"]["findings"] == 1
    assert data["coverage"][-1]["region"] == "eu-central-1"
    assert "Stats:" in result.stderr and "Snapshots saved:" in result.stderr
    assert len(list(destination.glob("*.json"))) == 3
    assert factory.call_args.kwargs["region"] == "eu-west-1"


def test_invalid_regional_snapshot_does_not_stop_other_regions(context, monkeypatch):
    from awsherlock.snapshot import SnapshotError
    calls = []
    install_regional_collectors(monkeypatch, calls)
    valid = capture_snapshot(replace(context, region="eu-central-1"), ["ec2"])
    monkeypatch.setattr("awsherlock.regional.capture_snapshot", Mock(side_effect=[SnapshotError("private-marker"), valid]))
    report = scan_regions(context, ["ec2"], ["eu-west-1", "eu-central-1"])
    assert report.incomplete and len(report.findings) == 1
    assert [entry["status"] for entry in report.coverage] == ["ERROR", "COMPLETE"]
    assert "private-marker" not in json.dumps(report.to_dict())


@pytest.mark.parametrize("args", [
    ["--timeout", "3"], ["--read-timeout", "3"], ["--regions", "eu-west-1"],
    ["--save-snapshot", "never-created.json"],
])
def test_offline_rejects_live_only_controls(args, no_aws, tmp_path):
    result = CliRunner().invoke(app, ["scan", str(tmp_path / "unused.json"), *args])
    assert result.exit_code == 2
    no_aws.assert_not_called()


def test_offline_rejects_explicit_worker_count(no_aws, tmp_path):
    result = CliRunner().invoke(app, ["scan", str(tmp_path / "unused.json"), "--max-workers", "2"])
    assert result.exit_code == 2
    no_aws.assert_not_called()


@pytest.mark.parametrize("value", ["0", "-1", str(len(SERVICES) + 1), "many"])
def test_invalid_worker_count_fails_before_aws(value, no_aws):
    result = CliRunner().invoke(app, ["scan", "--max-workers", value])
    assert result.exit_code == 2
    no_aws.assert_not_called()


def test_preview_reports_worker_count_without_aws(no_aws):
    result = CliRunner().invoke(app, ["scan", "--preview", "--preview-format", "json",
                                           "--max-workers", "4"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["options"]["max_workers"] == 4
    no_aws.assert_not_called()


def test_live_scan_forwards_explicit_worker_count(snapshot, context, monkeypatch):
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    collect = Mock(return_value=snapshot)
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", collect)
    result = CliRunner().invoke(app, ["scan", "--max-workers", "2", "--output", "json",
                                           "--no-progress"])
    assert result.exit_code == 1
    assert collect.call_args.kwargs["max_workers"] == 2


def test_snapshot_command_forwards_explicit_worker_count(snapshot, context, monkeypatch, tmp_path):
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    collect = Mock(return_value=snapshot)
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", collect)
    result = CliRunner().invoke(app, ["snapshot", "--output", str(tmp_path / "facts.json"),
                                           "--max-workers", "3"])
    assert result.exit_code == 1
    assert collect.call_args.kwargs["max_workers"] == 3


def test_stats_measure_duration_without_adding_report_fields(snapshot, tmp_path, monkeypatch):
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    monkeypatch.setattr("awsherlock.cli.perf_counter", Mock(side_effect=[10.0, 12.5]))
    result = CliRunner().invoke(app, ["scan", str(path), "--stats", "--no-progress", "--output", "json"])
    assert "Stats: 2.500s elapsed" in result.stderr
    assert json.loads(result.stdout) == evaluate_snapshot(snapshot).to_dict()


def test_guard_creates_no_snapshot_artifact(session_factory, tmp_path):
    destination = tmp_path / "facts"
    result = CliRunner().invoke(app, ["scan", "--expect-account", "999999999999",
                                    "--regions", "eu-west-1,eu-central-1",
                                    "--save-snapshot", str(destination), "--no-progress"])
    assert result.exit_code == 1 and not destination.exists()


def test_organization_discovery_failure_does_not_claim_saved_files(context, monkeypatch, tmp_path):
    from botocore.exceptions import ClientError
    source = replace(context, region="eu-west-1")
    source.session.client.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "ListAccounts")
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=source))
    destination = tmp_path / "bundle"
    result = CliRunner().invoke(app, ["scan", "organization", "--save-snapshot", str(destination),
                                    "--regions", "eu-west-1,eu-central-1", "--output", "json", "--no-progress"])
    assert result.exit_code == 1 and json.loads(result.stdout)["summary"]["incomplete"]
    assert "No snapshots saved:" in result.stderr and not destination.exists()


def test_snapshot_command_request_controls_reach_auth(snapshot, context, monkeypatch, tmp_path):
    factory = Mock(return_value=context)
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", Mock(return_value=snapshot))
    result = CliRunner().invoke(app, ["snapshot", "--output", str(tmp_path / "facts.json"),
                                    "--region", "eu-west-1", "--expect-account", context.account_id,
                                    "--connect-timeout", "2", "--read-timeout", "5", "--color", "never"])
    assert result.exit_code == 1 and "\x1b" not in result.stdout
    options = factory.call_args.kwargs
    assert options["region"] == "eu-west-1" and options["expect_account"] == context.account_id
    assert options["client_config"].connect_timeout == 2 and options["client_config"].read_timeout == 5


def test_identical_shadow_trail_findings_are_not_repeated(context, monkeypatch):
    def collect(target):
        resource = Resource(service="cloudtrail", resource_type="trail", account_id=target.account_id,
                            region="eu-west-1", resource_id="shared-trail", resource_arn=None,
                            data={"trail_settings": {"IsMultiRegionTrail": True,
                                                     "IncludeGlobalServiceEvents": True,
                                                     "LogFileValidationEnabled": False,
                                                     "IsOrganizationTrail": False}})
        return CollectionResult([resource], [])
    monkeypatch.setattr("awsherlock.snapshot.service_components", lambda service: (collect, service_components(service)[1]))
    report = scan_regions(context, ["cloudtrail"], ["eu-west-1", "eu-central-1"])
    assert len(report.findings) == 1
    assert sum(entry["findings"] for entry in report.coverage) == 1
    assert sum(entry["evaluated"] for entry in report.coverage) == 4


@pytest.mark.parametrize("top,child", [("always", "never"), ("never", "auto"), ("always", "auto")])
def test_nested_color_preferences_reset_after_command(snapshot, tmp_path, top, child):
    from typer import rich_utils
    prior = (rich_utils.FORCE_TERMINAL, rich_utils.COLOR_SYSTEM)
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    result = CliRunner().invoke(app, ["--color", top, "scan", str(path), "--color", child,
                                    "--output", "json", "--no-progress"])
    assert result.exit_code == 1 and "\x1b" not in result.stdout
    assert COLOR_MODE.get() == "auto"
    assert (rich_utils.FORCE_TERMINAL, rich_utils.COLOR_SYSTEM) == prior


@pytest.mark.parametrize("no_color", [False, True])
def test_explicit_always_colors_work_on_redirected_windows_output(monkeypatch, no_color):
    if no_color:
        monkeypatch.setenv("NO_COLOR", "1")
    else:
        monkeypatch.delenv("NO_COLOR", raising=False)
    result = CliRunner().invoke(app, ["--color", "always", "--list-services"], color=True)
    assert result.exit_code == 0
    assert ("\x1b[" in result.stdout) == (not no_color)
    assert COLOR_MODE.get() == "auto"


def test_scan_regions_exposes_already_evaluated_scope(context, snapshot, monkeypatch):
    captured = []
    monkeypatch.setattr("awsherlock.regional.capture_snapshot",
                        Mock(return_value=snapshot))
    report = scan_regions(
        context, ["s3"], ["eu-west-1"],
        evaluated_scope_sink=lambda saved, evaluated: captured.append((saved, evaluated)),
    )
    assert len(captured) == 1
    assert captured[0][0] is snapshot
    assert captured[0][1].findings == report.findings
