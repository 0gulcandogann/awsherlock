"""Basic CLI behavior; no AWS credentials or network access required."""

from unittest.mock import ANY, Mock
import subprocess

import pytest
from typer.testing import CliRunner

from awsherlock import __version__
from awsherlock.branding import ASCII_WORDMARK
from awsherlock.cli import app
from awsherlock.aws.context import ScanContext
from awsherlock.aws.session import SessionError
from awsherlock.evaluation import Report
from awsherlock.scanner import DEFAULT_SERVICES

runner = CliRunner()


@pytest.fixture(autouse=True)
def context_factory(monkeypatch: pytest.MonkeyPatch) -> Mock:
    factory = Mock(side_effect=AssertionError("Help/version must not create AWS sessions"))
    monkeypatch.setattr("awsherlock.cli.create_scan_context", factory)
    return factory


def test_help() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "AWSherlock" in result.output
    assert "AWS security scanner" in result.output
    assert "scan" in result.output
    assert "--update" in result.output


@pytest.mark.parametrize("args", [[], ["--help"]])
def test_root_usage_guide_is_available_without_aws(args, context_factory):
    result = runner.invoke(app, args, terminal_width=120, env={"COLUMNS": "120"})
    assert result.exit_code == 0
    assert "Quick start" in result.output
    assert "awsherlock scan --profile production" in result.output
    assert "awsherlock scan facts.json" in result.output
    assert "awsherlock scan --help" in result.output
    assert "awsherlock snapshot --help" in result.output
    assert "#command-reference" in result.output
    context_factory.assert_not_called()


@pytest.mark.parametrize("command", ["scan", "snapshot"])
def test_subcommand_help_has_examples_and_requirements(command, context_factory):
    result = runner.invoke(app, [command, "--help"], terminal_width=120, env={"COLUMNS": "120"})
    assert result.exit_code == 0 and "Examples" in result.output
    if command == "scan":
        assert "awsherlock scan --save-snapshot facts.json --stats" in result.output
        assert "Use --region OR --regions" in result.output
        assert "Offline scans reject AWS" in result.output
    else:
        assert "awsherlock snapshot --output facts.json" in result.output
        assert "required new JSON file path" in result.output
        assert "Assumed-role session name" in result.output
        assert "External ID required" in result.output
    context_factory.assert_not_called()


@pytest.mark.parametrize("width", [60, 80, 180])
@pytest.mark.parametrize("args", [["--help"], ["scan", "--help"], ["snapshot", "--help"]])
def test_boxed_help_fits_current_terminal_width(width, args) -> None:
    result = runner.invoke(app, args, env={"COLUMNS": str(width)}, terminal_width=width)
    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert "--help" in result.output
    assert "│" in result.output and "─" in result.output
    assert max(map(len, result.output.splitlines())) <= width


def test_update_uses_current_python_and_main_branch(monkeypatch) -> None:
    run = Mock()
    monkeypatch.setattr("awsherlock.cli.subprocess.run", run)

    result = runner.invoke(app, ["--update"])

    assert result.exit_code == 0
    run.assert_called_once_with(
        [
            __import__("sys").executable,
            "-m",
            "pip",
            "install",
            "--upgrade",
            "--force-reinstall",
            "git+https://github.com/0gulcandogann/awsherlock.git@main",
        ],
        check=True,
    )


def test_update_reports_pip_failure(monkeypatch) -> None:
    monkeypatch.setattr(
        "awsherlock.cli.subprocess.run",
        Mock(side_effect=subprocess.CalledProcessError(1, "pip")),
    )

    result = runner.invoke(app, ["--update"])

    assert result.exit_code == 1
    assert "Update failed" in result.output


def test_bare_command_shows_help_without_aws(context_factory: Mock) -> None:
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "AWSherlock" in result.output
    assert "scan" in result.output and "snapshot" in result.output
    assert "Missing command" not in result.output
    context_factory.assert_not_called()
    assert ASCII_WORDMARK in result.output


def test_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == f"AWSherlock {__version__}"


def test_scan_help() -> None:
    result = runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "Identify the AWS account" in result.output
    assert "--services" in result.output


@pytest.mark.parametrize("profile", [None, "production"])
def test_scan_defaults_to_all_services(context_factory: Mock, profile: str | None, monkeypatch) -> None:
    context_factory.side_effect = None
    context_factory.return_value = ScanContext(
        account_id="123456789012",
        caller_arn="arn:aws:iam::123456789012:user/test",
        partition="aws", profile=profile, region=None, session=Mock(),
    )
    args = ["scan"] + (["--profile", profile] if profile else [])
    capture = Mock()
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", capture)
    monkeypatch.setattr("awsherlock.cli.evaluate_snapshot", Mock(return_value=Report({"account_id": "123456789012"}, [], [])))
    result = runner.invoke(app, args)

    assert result.exit_code == 0
    context_factory.assert_called_once_with(
        profile=profile, role=None, role_session_name=None, external_id=None,
    )
    assert "Account: 123456789012" in result.output
    capture.assert_called_once_with(context_factory.return_value, list(DEFAULT_SERVICES), progress=ANY)


def test_scan_error(context_factory: Mock) -> None:
    context_factory.side_effect = SessionError("AccessDenied: identity unavailable.")
    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 1
    assert "AccessDenied" in result.stderr
    assert "Account:" not in result.output
    assert "PASS" not in result.output


def test_scan_role_options(context_factory: Mock, monkeypatch) -> None:
    context_factory.side_effect = None
    context_factory.return_value = ScanContext(
        account_id="999999999999",
        caller_arn="arn:aws:sts::999999999999:assumed-role/Audit/audit-session",
        partition="aws", profile="production", region="eu-central-1", session=Mock(),
    )
    role = "arn:aws:iam::999999999999:role/Audit"
    monkeypatch.setattr("awsherlock.cli.capture_snapshot", Mock())
    monkeypatch.setattr("awsherlock.cli.evaluate_snapshot", Mock(return_value=Report({"account_id": "999999999999"}, [], [])))
    result = runner.invoke(app, [
        "scan", "--profile", "production", "--role", role,
        "--role-session-name", "audit-session", "--external-id", "external-marker",
    ])
    assert result.exit_code == 0
    context_factory.assert_called_once_with(
        profile="production", role=role,
        role_session_name="audit-session", external_id="external-marker",
    )
    assert "Account: 999999999999" in result.output
    assert "external-marker" not in result.output
