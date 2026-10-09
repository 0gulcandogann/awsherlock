"""Identity visibility regressions: synthetic contexts, no real AWS access."""

from dataclasses import replace
from unittest.mock import Mock
import json

import pytest
from botocore.exceptions import SSOTokenLoadError, UnauthorizedSSOTokenError, EndpointConnectionError
from typer.testing import CliRunner

from awsherlock.aws.context import ScanContext
from awsherlock.aws.session import SessionError, create_scan_context
from awsherlock.aws.profiles import list_profiles, ProfileMetadata
from awsherlock.cli import app
from awsherlock.evaluation import Report
from awsherlock.organization import scan_organization
from awsherlock.snapshot import write_snapshot
from test_snapshot import snapshot

runner = CliRunner()


@pytest.fixture
def context():
    return ScanContext("123456789012", "arn:aws:sts::123456789012:assumed-role/AuditRole/test",
                       "aws", "production", "eu-central-1", Mock())


@pytest.mark.parametrize("resource,label", [
    ("assumed-role/AuditRole/test", "assumed role"),
    ("user/team/alice", "IAM user"), ("root", "root"),
    ("federated-user/alice", "federated user"), ("other", "unknown"),
])
def test_whoami_identity_types_without_collection(context, monkeypatch, resource, label):
    service = "sts" if resource.startswith(("assumed-role/", "federated-user/")) else "iam"
    context = replace(context, caller_arn=f"arn:aws:{service}::123456789012:{resource}")
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    collect = Mock(side_effect=AssertionError("whoami must not collect"))
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", collect)
    result = runner.invoke(app, ["whoami", "--profile", "production"])
    assert result.exit_code == 0, result.output
    assert f"Principal: {label}" in result.stdout
    assert context.caller_arn in result.stdout
    assert "does not prove scanner permission coverage" in result.stdout
    assert not result.stderr
    collect.assert_not_called()


def test_whoami_role_and_guard_options(context, monkeypatch):
    factory = Mock(return_value=context)
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    role = "arn:aws:iam::123456789012:role/team/AuditRole"
    result = runner.invoke(app, ["whoami", "--role", role, "--external-id", "private-external",
                                "--role-session-name", "audit", "--region", "eu-west-1",
                                "--expect-account", context.account_id, "--timeout", "7"])
    assert result.exit_code == 0
    options = factory.call_args.kwargs
    assert options["role"] == role and options["external_id"] == "private-external"
    assert options["role_session_name"] == "audit" and options["region"] == "eu-west-1"
    assert options["expect_account"] == context.account_id
    assert options["client_config"].connect_timeout == 7
    assert "private-external" not in result.output
    assert ":role/team/" not in result.output  # no inferred IAM role path


@pytest.mark.parametrize("args", [["--timeout", "0"], ["--expect-account", "bad"]])
def test_whoami_invalid_options_before_authentication(monkeypatch, args):
    factory = Mock()
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    assert runner.invoke(app, ["whoami", *args]).exit_code == 2
    factory.assert_not_called()


def test_guard_failure_does_not_show_verified_identity(context, monkeypatch):
    factory = Mock(side_effect=SessionError("AWS account does not match --expect-account."))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    collect = Mock()
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", collect)
    for args in (["whoami"], ["scan", "--no-progress"]):
        result = runner.invoke(app, args)
        assert result.exit_code == 1 and not result.stdout
        assert "verified live" not in result.stderr
    collect.assert_not_called()


def test_live_summary_before_collection_and_json_clean(context, monkeypatch):
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    seen = []
    from awsherlock.identity_display import show_identity
    def show(*args, **kwargs):
        seen.append("identity")
        show_identity(*args, **kwargs)
    def capture(*args, **kwargs):
        assert seen == ["identity"]
        seen.append("collection")
        return Mock()
    monkeypatch.setattr("awsherlock.cli.show_identity", show)
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", capture)
    monkeypatch.setattr("awsherlock.cli.evaluate_snapshot", Mock(return_value=Report({}, [], [])))
    result = runner.invoke(app, ["scan", "--output", "json", "--services", "s3", "--no-progress"])
    assert result.exit_code == 0, result.output
    json.loads(result.stdout)
    assert "verified live via STS" in result.stderr and "Services: s3" in result.stderr
    assert "source account is not separately verified" in result.stderr


def test_offline_summary_is_snapshot_metadata(snapshot, monkeypatch, tmp_path):
    path = tmp_path / "snapshot.json"
    write_snapshot(snapshot, path)
    factory = Mock(side_effect=AssertionError("offline must not authenticate"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    result = runner.invoke(app, ["scan", str(path), "--output", "json"])
    assert result.exit_code == 1  # fixture deliberately has AccessDenied
    assert json.loads(result.stdout)["coverage"][0]["status"] != "COMPLETE"
    assert "snapshot metadata; not verified live" in result.stderr
    assert "Live identity: not checked" in result.stderr
    assert "verified live via STS" not in result.stderr
    factory.assert_not_called()


def test_multiregion_summary_once_with_selected_scope(context, monkeypatch):
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    scan = Mock(return_value=Report({}, [], []))
    monkeypatch.setattr("awsherlock.cli.scan_regions", scan)
    result = runner.invoke(app, ["scan", "--regions", "eu-central-1,eu-west-1",
                                "--services", "s3,ec2", "--output", "json"])
    assert result.exit_code == 0, result.output
    json.loads(result.stdout)
    assert result.stderr.count("Identity: verified live via STS") == 1
    assert "Regions: eu-central-1, eu-west-1" in result.stderr
    assert "Services: s3, ec2" in result.stderr
    assert scan.call_args.args[2] == ["eu-central-1", "eu-west-1"]


def test_whoami_real_session_layer_account_guard(context, monkeypatch):
    monkeypatch.setattr("awsherlock.aws.session.boto3.Session", Mock(return_value=context.session))
    context.session.profile_name = "production"
    context.session.region_name = context.region
    context.session.client.return_value.get_caller_identity.return_value = {
        "Account": context.account_id, "Arn": context.caller_arn, "UserId": "NOT_FOR_OUTPUT"}
    result = runner.invoke(app, ["whoami", "--expect-account", "999999999999"])
    assert result.exit_code == 1 and not result.stdout
    assert "does not match" in result.stderr and "NOT_FOR_OUTPUT" not in result.output


def test_organization_identity_only_for_authenticated_targets(context, snapshot, monkeypatch):
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = [
        {"Accounts": [{"Id": "000000000001", "Name": "one", "State": "ACTIVE"},
                      {"Id": "000000000002", "Name": "two", "State": "ACTIVE"}]}]
    target = replace(context, account_id="000000000001",
                     caller_arn="arn:aws:sts::000000000001:assumed-role/AuditRole/test")
    monkeypatch.setattr("awsherlock.organization.create_scan_context",
                        Mock(side_effect=[target, SessionError("AccessDenied")]))
    events = []
    def capture(received, services):
        assert events == [target]
        return replace(snapshot, metadata=replace(snapshot.metadata, account_id=received.account_id),
                       services={"s3": type(snapshot.services["s3"])([], [])})
    monkeypatch.setattr("awsherlock.organization.capture_snapshot", capture)
    report = scan_organization(context, ["s3"], identity_callback=events.append)
    assert events == [target]
    assert report.incomplete


@pytest.mark.parametrize("command", [["--help"], ["whoami", "--help"],
                                     ["profiles", "--help"], ["profiles", "list", "--help"], ["--doctor"]])
def test_help_and_doctor_do_not_authenticate(monkeypatch, command):
    factory = Mock(side_effect=AssertionError("no authentication"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    monkeypatch.setattr("awsherlock.cli.list_profiles", Mock(side_effect=AssertionError("no profile inspection")))
    result = runner.invoke(app, command)
    assert result.exit_code == 0, result.output
    factory.assert_not_called()


def test_profile_metadata_no_provider_resolution(tmp_path, monkeypatch):
    config = tmp_path / "config"
    credentials = tmp_path / "credentials"
    config.write_text("[profile sso]\nregion=eu-west-1\nsso_session=work\n"
                      "[profile process]\ncredential_process=DO_NOT_EXECUTE\n"
                      "[sso-session work]\nsso_start_url=https://example.invalid\n", encoding="utf-8")
    credentials.write_text("[legacy]\naws_access_key_id=SECRET_ID\naws_secret_access_key=SECRET_VALUE\n", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials))
    forbid = Mock(side_effect=AssertionError("profile metadata must not resolve credentials or create clients"))
    monkeypatch.setattr("botocore.session.Session.get_credentials", forbid)
    monkeypatch.setattr("botocore.session.Session.create_client", forbid)
    assert [(p.name, p.region) for p in list_profiles()] == [("legacy", None), ("process", None), ("sso", "eu-west-1")]
    result = runner.invoke(app, ["profiles", "list"])
    assert result.exit_code == 0, result.output
    assert "legacy" in result.stdout and "unknown" in result.stdout
    assert "Configured region" in result.stdout and "Not verified" in result.stdout
    assert "eu-west-1" in result.stdout
    assert not any(s in result.output for s in ("SECRET_ID", "SECRET_VALUE", "DO_NOT_EXECUTE", "sso_start_url"))
    forbid.assert_not_called()


@pytest.mark.parametrize("contents", [None, "[broken\nsecret-marker", "[profile a]\nregion=x\nregion=y\n"])
def test_empty_or_malformed_profile_configuration(tmp_path, monkeypatch, contents):
    path = tmp_path / "config"
    if contents is not None:
        path.write_text(contents, encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(path))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "missing"))
    result = runner.invoke(app, ["profiles", "list"])
    assert result.exit_code == (0 if contents is None else 1)
    assert "secret-marker" not in result.output
    if contents is None:
        assert "No configured AWS profiles" in result.stdout
    else:
        assert not result.stdout


@pytest.mark.parametrize("error,recovery", [
    (SSOTokenLoadError(error_msg="secret-marker"), "sso"),
    (UnauthorizedSSOTokenError(), "sso"),
    (EndpointConnectionError(endpoint_url="https://secret-marker.invalid"), None),
])
def test_sdk_errors_classified_without_payloads(context, monkeypatch, error, recovery):
    factory = Mock(return_value=context.session)
    monkeypatch.setattr("awsherlock.aws.session.boto3.Session", factory)
    context.session.client.return_value.get_caller_identity.side_effect = error
    with pytest.raises(SessionError) as caught:
        create_scan_context("production")
    assert caught.value.recovery == recovery
    assert "secret-marker" not in str(caught.value)
    result = runner.invoke(app, ["whoami", "--profile", "production"])
    assert result.exit_code == 1 and not result.stdout
    assert ("aws sso login" in result.stderr) == (recovery == "sso")
    assert "secret-marker" not in result.output


def test_recovery_for_missing_profile_and_controls(context, monkeypatch):
    monkeypatch.setattr("awsherlock.cli.create_scan_context",
                        Mock(side_effect=SessionError("Profile not found", recovery="profiles")))
    assert "Next: awsherlock profiles list" in runner.invoke(app, ["whoami"]).stderr
    context = replace(context, profile="bad\x1b[2J\nname")
    monkeypatch.setattr("awsherlock.cli.create_scan_context", Mock(return_value=context))
    result = runner.invoke(app, ["whoami", "--color", "never"], env={"NO_COLOR": "1", "COLUMNS": "40"})
    assert result.exit_code == 0 and "\x1b" not in result.stdout
    assert "\\x1b" in result.stdout and "\\n" in result.stdout


@pytest.mark.parametrize("width", [40, 60, 100])
def test_profile_table_fits_terminal_width(monkeypatch, width):
    monkeypatch.setattr("awsherlock.cli.list_profiles", Mock(return_value=[
        ProfileMetadata("production-audit-with-a-long-profile-name", "eu-central-1"),
        ProfileMetadata("dev", None)]))
    result = runner.invoke(app, ["profiles", "list", "--color", "never"],
                           env={"COLUMNS": str(width)}, terminal_width=width)
    assert result.exit_code == 0, result.output
    assert "AWS profiles (2 configured)" in result.stdout
    assert max(map(len, result.stdout.splitlines())) <= width
    assert "│" in result.stdout
    assert "\x1b" not in result.stdout
    if width == 100:
        assert "production-audit-with-a-long-profile-name" in result.stdout
        assert "Configured region" in result.stdout and "Not verified" in result.stdout


@pytest.mark.parametrize("args,env,colored", [
    ([], {}, False), (["--color", "always"], {}, True),
    (["--color", "never"], {}, False), ([], {"NO_COLOR": "1"}, False),
])
def test_profile_table_color_modes_and_redirect(monkeypatch, args, env, colored):
    monkeypatch.setattr("awsherlock.cli.list_profiles", Mock(return_value=[ProfileMetadata("dev", None)]))
    result = runner.invoke(app, ["profiles", "list", *args], env={"COLUMNS": "100", **env})
    assert result.exit_code == 0, result.output
    assert ("\x1b[" in result.stdout) == colored
    assert "Not verified" in result.stdout and "unknown" in result.stdout
    assert not result.stderr


def test_profile_table_escapes_controls_and_keeps_markup_literal(monkeypatch):
    monkeypatch.setattr("awsherlock.cli.list_profiles", Mock(return_value=[
        ProfileMetadata("[red]dev\x1b[2J", "bad\nregion")]))
    result = runner.invoke(app, ["profiles", "list", "--color", "never"], env={"COLUMNS": "100"})
    assert result.exit_code == 0, result.output
    assert "[red]dev\\x1b[2J" in result.stdout and "bad\\nregion" in result.stdout
    assert "\x1b" not in result.stdout
