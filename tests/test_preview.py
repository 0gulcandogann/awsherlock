"""Local scan plans never authenticate, collect, evaluate or create outputs."""

from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.snapshot import write_snapshot
from test_snapshot import snapshot


@pytest.fixture
def forbidden_work(monkeypatch):
    blocked = Mock(side_effect=AssertionError("Preview must not start scan work"))
    for name in ("create_scan_context", "capture_snapshot", "scan_organization",
                 "scan_regions", "evaluate_snapshot", "write_report", "snapshot_saver"):
        monkeypatch.setattr(f"awsherlock.cli.{name}", blocked)
    return blocked


def test_live_preview_shows_selection_and_creates_no_files(tmp_path, forbidden_work, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret-marker")
    destination = tmp_path / "report.json"
    facts = tmp_path / "facts.json"
    result = CliRunner().invoke(app, ["scan", "--preview", "--profile", "prod",
        "--services", "iam,s3", "--checks", "AWSH-S3-001", "--resources", "bucket-a",
        "--region", "eu-west-1", "--output", "json", "--report-file", str(destination),
        "--save-snapshot", str(facts), "--external-id", "private-external"])
    assert result.exit_code == 0, result.output
    assert "Identity and credential availability: unverified" in result.output
    assert "Services: iam, s3" in result.output
    assert "Checks for evaluation: AWSH-S3-001" in result.output
    assert "collection scope is unchanged" in result.output
    assert "report.json" in result.output and "facts.json" in result.output
    assert "private-external" not in result.output and "secret-marker" not in result.output
    assert not destination.exists() and not facts.exists()
    forbidden_work.assert_not_called()


def test_organization_preview_does_not_discover_membership(forbidden_work):
    result = CliRunner().invoke(app, ["scan", "organization", "--preview", "--accounts",
        "123456789012", "--ous", "ou-abcd-12345678", "--role-name", "audit/Reader"])
    assert result.exit_code == 0, result.output
    assert "Requested accounts: 123456789012" in result.output
    assert "Requested OUs: ou-abcd-12345678" in result.output
    assert "Organization membership and target identities: not discovered" in result.output
    assert "Target role: audit/Reader" in result.output
    forbidden_work.assert_not_called()


def test_offline_preview_reads_metadata_without_evaluation(snapshot, tmp_path, forbidden_work):
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    result = CliRunner().invoke(app, ["scan", str(path), "--preview", "--services", "s3",
        "--checks", "AWSH-S3-001", "--expect-account", snapshot.metadata.account_id])
    assert result.exit_code == 0, result.output
    assert f"Snapshot account: {snapshot.metadata.account_id}" in result.output
    assert "no live verification" in result.output
    assert "Services: s3" in result.output
    forbidden_work.assert_not_called()


@pytest.mark.parametrize("options", [
    ["--services", "lambda"], ["--expect-account", "999999999999"]])
def test_offline_preview_rejects_missing_scope_or_wrong_account(snapshot, tmp_path, forbidden_work, options):
    path = tmp_path / "facts.json"
    write_snapshot(snapshot, path)
    result = CliRunner().invoke(app, ["scan", str(path), "--preview", *options])
    assert result.exit_code == 1
    assert "Scan preview:" not in result.output
    forbidden_work.assert_not_called()


def test_preview_is_readable_without_color_at_narrow_width(forbidden_work):
    result = CliRunner().invoke(app, ["scan", "--preview", "--color", "never",
                                      "--services", "iam,s3"], terminal_width=60,
                                env={"COLUMNS": "60", "NO_COLOR": "1"})
    assert result.exit_code == 0, result.output
    assert "Identity and credential availability: unverified" in result.output
    assert "\x1b[" not in result.output
    assert max(map(len, result.output.splitlines())) <= 60
    forbidden_work.assert_not_called()


@pytest.mark.parametrize("args", [
    ["--services", "unknown"], ["--checks", "unknown"],
    ["--services", "iam", "--checks", "AWSH-S3-001"],
    ["--accounts", "123456789012"], ["--region", "bad region"],
    ["--timeout", "0"], ["--resources", "*"]])
def test_invalid_preview_fails_before_work(args, forbidden_work):
    result = CliRunner().invoke(app, ["scan", "--preview", *args])
    assert result.exit_code == 2
    forbidden_work.assert_not_called()


def test_preview_escapes_control_characters(forbidden_work):
    result = CliRunner().invoke(app, ["scan", "--preview", "--profile", "prod\x1b[2J"])
    assert result.exit_code == 0, result.output
    assert "prod\\x1b[2J" in result.output and "prod\x1b[2J" not in result.output
    forbidden_work.assert_not_called()
