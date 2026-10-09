"""Offline discovery and display switches preserve scan data and exit status."""

from io import StringIO
import json
from unittest.mock import Mock

import pytest
from rich.console import Console
from typer.testing import CliRunner

from awsherlock.catalog import check_catalog, describe_check
from awsherlock.cli import app
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.snapshot import write_snapshot
from test_snapshot import snapshot
from test_s3 import context
from dataclasses import replace


@pytest.fixture
def no_aws(monkeypatch):
    fail = Mock(side_effect=AssertionError("Discovery must not resolve credentials or call AWS"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", fail)
    monkeypatch.setattr("boto3.Session", fail)
    return fail


@pytest.mark.parametrize("option", ["--doctor", "--list-checks", "--list-services"])
def test_discovery_needs_no_aws_and_does_not_leak_environment(option, no_aws, monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access-key-marker")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret-marker")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "test-token-marker")
    monkeypatch.setenv("UNRELATED_PRIVATE_VALUE", "test-private-marker")
    result = CliRunner().invoke(app, [option])
    assert result.exit_code == 0
    assert "marker" not in result.output
    no_aws.assert_not_called()
    if option == "--doctor":
        assert "Python executable:" in result.output
        assert "Package path:" in result.output
        assert "Stderr terminal:" in result.output
    elif option == "--list-checks":
        assert "42 supported checks" in result.output
        assert "AWSH-CT-001" in result.output
        assert "AWSH-SECRET-003" in result.output
    else:
        assert "iam" in result.output and "12 checks" in result.output
        assert "s3" in result.output and "5 checks" in result.output


def test_service_catalog_marks_default_and_opt_in_services(no_aws):
    result = CliRunner().invoke(app, ["--list-services"])

    assert result.exit_code == 0
    lines = [line.strip() for line in result.output.splitlines() if "checks" in line]
    assert len(lines) == 11
    assert sum("Default" in line for line in lines) == 7
    assert sum("Opt-in" in line for line in lines) == 4
    assert any("iam" in line and "12 checks" in line and "Default" in line for line in lines)
    assert any("bedrock" in line and "2 checks" in line and "Opt-in" in line for line in lines)
    no_aws.assert_not_called()


def test_catalog_ids_are_unique_and_match_supported_check_families():
    catalog = check_catalog()
    ids = {entry[0] for entry in catalog}
    assert len(ids) == len(catalog) == 42
    expected = {f"AWSH-{prefix}-{number:03}" for prefix, count in
                (("IAM", 12), ("S3", 5), ("EC2", 6), ("LAMBDA", 3),
                 ("SECRET", 3), ("CT", 4), ("KMS", 2), ("RDS", 3), ("GD", 1),
                 ("DDB", 1), ("BEDROCK", 2))
                for number in range(1, count + 1)}
    assert ids == expected
    assert all(title for _, _, title in catalog)


@pytest.mark.parametrize("args", [
    ["--doctor", "--list-checks"], ["--list-services", "--list-checks"],
    ["--update", "--doctor"], ["--doctor", "scan"],
    ["--list-services", "scan"], ["--list-checks", "snapshot", "--output", "unused.json"],
])
def test_conflicting_actions_fail_before_work(args, no_aws, monkeypatch):
    updater = Mock(side_effect=AssertionError("Must not update"))
    monkeypatch.setattr("awsherlock.cli.update_installation", updater)
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 2
    no_aws.assert_not_called()
    updater.assert_not_called()


@pytest.mark.parametrize("mode", ["live", "offline", "organization"])
@pytest.mark.parametrize("options,banner,bar", [
    ([], True, True), (["--no-banner"], False, True),
    (["--no-progress"], False, False), (["--no-progress", "--no-banner"], False, False),
])
def test_display_switches_preserve_json_and_incomplete_exit(snapshot, context, tmp_path, monkeypatch,
                                                           mode, options, banner, bar):
    stream = StringIO()
    console = Console(file=stream, force_terminal=True, force_interactive=True,
                      width=100, legacy_windows=False, _environ={"TERM": "xterm"})
    monkeypatch.setattr("awsherlock.activity.Console", lambda **kwargs: console)
    monkeypatch.setattr("awsherlock.activity.terminal_banner", lambda **kwargs: "ASCII LOGO")
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", Mock(return_value=snapshot))
    report = evaluate_snapshot(snapshot)
    monkeypatch.setattr("awsherlock.cli.scan_organization", Mock(return_value=report))
    args = ["scan"]
    if mode == "offline":
        path = tmp_path / "snapshot.json"
        write_snapshot(snapshot, path)
        args.append(str(path))
    elif mode == "organization":
        args.append("organization")
    result = CliRunner().invoke(app, args + options + ["--output", "json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout) == report.to_dict()
    assert ("ASCII LOGO" in stream.getvalue()) == banner
    assert ("[####################]" in stream.getvalue()) == bar


def test_doctor_escapes_untrusted_launcher_path(no_aws, monkeypatch):
    monkeypatch.setattr("awsherlock.diagnostics.shutil.which", lambda name: "launcher\x1b[2J")
    result = CliRunner().invoke(app, ["--doctor"])
    assert result.exit_code == 0
    assert "launcher\\x1b[2J" in result.output
    assert "launcher\x1b[2J" not in result.output


@pytest.mark.parametrize("output", ["json", "html"])
def test_summary_only_rejects_file_formats_before_aws(output, no_aws):
    result = CliRunner().invoke(app, ["scan", "--summary-only", "--output", output])
    assert result.exit_code == 2
    assert "requires console output" in result.output
    no_aws.assert_not_called()


@pytest.mark.parametrize("mode", ["live", "offline", "organization"])
def test_verbose_keeps_json_and_incomplete_exit(snapshot, context, tmp_path, monkeypatch, mode):
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", Mock(return_value=snapshot))
    report = evaluate_snapshot(snapshot)
    monkeypatch.setattr("awsherlock.cli.scan_organization", Mock(return_value=report))
    args = ["scan"]
    if mode == "offline":
        path = tmp_path / "snapshot.json"
        write_snapshot(snapshot, path)
        args.append(str(path))
    elif mode == "organization":
        args.append("organization")
    result = CliRunner().invoke(app, args + ["--verbose", "--no-progress", "--output", "json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout) == report.to_dict()
    assert "[scan]" in result.stderr
    assert "Scan finished - incomplete coverage" in result.stderr


def test_summary_only_cli_preserves_denied_coverage(snapshot, tmp_path):
    path = tmp_path / "snapshot.json"
    write_snapshot(snapshot, path)
    result = CliRunner().invoke(app, ["scan", str(path), "--summary-only", "--no-progress"])
    assert result.exit_code == 1
    assert "Incomplete scan coverage" in result.stdout
    assert "Scan coverage" in result.stdout
    assert "checks evaluated" in result.stdout
    assert "Remediation:" not in result.stdout
    assert "Scan issues" in result.stderr
    assert "AWSH-S3-004 requires logging" in result.stderr
    assert "AccessDenied" in result.stderr


@pytest.mark.parametrize("args", [
    ["scan", "--region", "BAD"],
    ["scan", "unused.json", "--region", "eu-west-1"],
])
def test_region_invalid_or_offline_fails_before_aws(args, no_aws):
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 2
    no_aws.assert_not_called()


@pytest.mark.parametrize("organization", [False, True])
def test_region_reaches_scan_context_and_report(context, snapshot, monkeypatch, organization):
    target = replace(context, region="eu-west-1")
    factory = Mock(return_value=target)
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    selected_snapshot = replace(snapshot, metadata=replace(snapshot.metadata, region=target.region))
    capture = Mock(return_value=selected_snapshot)
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", capture)
    report = evaluate_snapshot(selected_snapshot)
    org = Mock(return_value=report)
    monkeypatch.setattr("awsherlock.cli.scan_organization", org)
    result = CliRunner().invoke(app, ["scan"] + (["organization"] if organization else []) +
                                ["--region", "eu-west-1", "--no-progress", "--output", "json"])
    assert result.exit_code == 1
    assert factory.call_args.kwargs["region"] == "eu-west-1"
    assert json.loads(result.stdout)["metadata"]["region"] == "eu-west-1"
    assert (org if organization else capture).call_args.args[0] is target


@pytest.mark.parametrize("identifier,service,title", check_catalog())
def test_every_check_can_be_described_without_aws_or_evaluation(identifier, service, title, no_aws, monkeypatch):
    from awsherlock.scanner import SERVICES, service_components
    fail = Mock(side_effect=AssertionError("Description must not evaluate rules"))
    for rule_type in {type(rule) for selected in SERVICES for rule in service_components(selected)[1]}:
        monkeypatch.setattr(rule_type, "evaluate", fail)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "private-secret-marker")
    result = CliRunner().invoke(app, ["--describe-check", identifier.lower()])
    assert result.exit_code == 0
    assert f"Check: {identifier}" in result.stdout
    assert f"Title: {title}" in " ".join(result.stdout.split())
    assert f"Service: {service}" in result.stdout
    assert "Required fact:" in result.stdout and "Remediation:" in result.stdout
    assert "Scope:" in result.stdout and "private-secret-marker" not in result.output
    fail.assert_not_called()
    no_aws.assert_not_called()


@pytest.mark.parametrize("args", [
    ["--describe-check", "AWSH-CT-001", "--doctor"],
    ["--describe-check", "AWSH-CT-001", "--update"],
    ["--describe-check", "AWSH-CT-001", "--list-checks"],
    ["--describe-check", "AWSH-CT-001", "--list-services"],
    ["--describe-check", "AWSH-CT-001", "scan"],
    ["--describe-check", "AWSH-UNKNOWN-999"],
    ["--describe-check", ""],
    ["--describe-check", "bad\x1b[2J"],
])
def test_invalid_descriptions_fail_before_work(args, no_aws, monkeypatch):
    updater = Mock(side_effect=AssertionError("Must not update"))
    monkeypatch.setattr("awsherlock.cli.update_installation", updater)
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 2
    assert "\x1b[2J" not in result.output
    no_aws.assert_not_called()
    updater.assert_not_called()


def test_s3_description_guidance_matches_actual_findings():
    from awsherlock.models import Resource
    from awsherlock.rules.s3 import S3_RULES
    resource = Resource(service="s3", resource_type="bucket", account_id="123456789012",
                        region="eu-west-1", resource_id="example-bucket", resource_arn=None,
                        data={"public_access_block": None, "encryption": None,
                              "versioning": None, "logging": None, "policy_public": True})
    for rule in S3_RULES:
        finding = rule.evaluate(resource)[0]
        details = describe_check(finding.id)
        assert details["Title"] == finding.title
        assert details["Remediation"] == finding.remediation
