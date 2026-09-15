"""Basic CLI behavior; no AWS credentials or network access required."""

from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock import __version__
from awsherlock.cli import app
from awsherlock.aws.context import ScanContext
from awsherlock.aws.session import SessionError

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


def test_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == f"AWSherlock {__version__}"


def test_scan_help() -> None:
    result = runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "Identify the AWS account" in result.output
    assert "not implemented yet" in result.output


@pytest.mark.parametrize("profile", [None, "production"])
def test_scan_identity(context_factory: Mock, profile: str | None) -> None:
    context_factory.side_effect = None
    context_factory.return_value = ScanContext(
        account_id="123456789012",
        caller_arn="arn:aws:iam::123456789012:user/test",
        partition="aws", profile=profile, region=None, session=Mock(),
    )
    args = ["scan"] + (["--profile", profile] if profile else [])
    result = runner.invoke(app, args)

    assert result.exit_code == 0
    context_factory.assert_called_once_with(profile=profile)
    assert "Account: 123456789012" in result.output
    assert "Region: not configured" in result.output
    assert "Security scanning is not implemented yet" in result.output
    assert "No security checks were run" in result.output


def test_scan_error(context_factory: Mock) -> None:
    context_factory.side_effect = SessionError("AccessDenied: identity unavailable.")
    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 1
    assert "AccessDenied" in result.stderr
    assert "Account:" not in result.output
    assert "PASS" not in result.output
