"""The guided command only prepares a live scan invocation."""

from unittest.mock import Mock
import sys

import pytest
from typer.testing import CliRunner

from awsherlock.aws.profiles import ProfileMetadata
from awsherlock.cli import app


@pytest.fixture
def local_guide(monkeypatch):
    monkeypatch.setattr("awsherlock.cli._interactive_terminal", lambda: True)
    monkeypatch.setattr("awsherlock.cli.list_profiles", lambda: [
        ProfileMetadata("production team", "eu-central-1"),
        ProfileMetadata("other", None),
    ])
    blocked = Mock(side_effect=AssertionError("guide must not scan or write"))
    for name in ("create_scan_context", "capture_snapshot", "scan_organization",
                 "scan_regions", "evaluate_snapshot", "write_report", "snapshot_saver"):
        monkeypatch.setattr(f"awsherlock.cli.{name}", blocked)
    return blocked


def test_guide_selected_profile_region_and_services(local_guide):
    result = CliRunner().invoke(app, ["guide"], input="1\neu-west-1\n1,3\n")
    assert result.exit_code == 0, result.output
    assert "Profile: production team" in result.output
    assert "Regions: eu-west-1" in result.output
    assert "Services: iam, ec2" in result.output
    assert "Identity and credential availability: unverified" in result.output
    expected = (
        "awsherlock scan --profile 'production team' --region 'eu-west-1' --services 'iam,ec2'"
        if sys.platform == "win32"
        else "awsherlock scan --profile 'production team' --region eu-west-1 --services iam,ec2"
    )
    assert expected in result.output
    local_guide.assert_not_called()


def test_guide_sdk_defaults_and_all_services(local_guide):
    result = CliRunner().invoke(app, ["guide", "--color", "never"], input="0\n\nall\n",
                                terminal_width=60, env={"COLUMNS": "60", "NO_COLOR": "1"})
    assert result.exit_code == 0, result.output
    assert "Profile: SDK default chain (unverified)" in result.output
    assert "Regions: SDK default (unverified)" in result.output
    assert "awsherlock scan\n" in result.output
    assert "\x1b[" not in result.output
    assert max(map(len, result.output.splitlines())) <= 60
    local_guide.assert_not_called()


def test_guide_noninteractive_exits_before_local_reads(monkeypatch):
    reader = Mock(side_effect=AssertionError("non-TTY must not read profiles"))
    monkeypatch.setattr("awsherlock.cli.list_profiles", reader)
    monkeypatch.setattr("awsherlock.cli._interactive_terminal", lambda: False)
    result = CliRunner().invoke(app, ["guide"])
    assert result.exit_code == 2
    assert "scan --preview" in result.output
    reader.assert_not_called()


@pytest.mark.parametrize("answers", [
    "3\n", "1,2\n", "1\nbad region\n", "1\neu-west-1\n0\n",
    "1\neu-west-1\n12\n", "1\neu-west-1\n1,nope\n", "999999999999999999999999\n",
])
def test_guide_invalid_selection_never_scans(local_guide, answers):
    result = CliRunner().invoke(app, ["guide"], input=answers)
    assert result.exit_code == 2, result.output
    assert "Run this command to scan" not in result.output
    local_guide.assert_not_called()


def test_guide_rejects_control_characters_in_profile(local_guide, monkeypatch):
    monkeypatch.setattr("awsherlock.cli.list_profiles", lambda: [ProfileMetadata("prod\x1b[2J", None)])
    result = CliRunner().invoke(app, ["guide"], input="1\n")
    assert result.exit_code == 2
    assert "prod\\x1b[2J" in result.output
    assert "prod\x1b[2J" not in result.output
    local_guide.assert_not_called()


def test_guide_cancelled_before_scan(local_guide, monkeypatch):
    def cancel(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr("awsherlock.cli.typer.prompt", cancel)
    result = CliRunner().invoke(app, ["guide"])
    assert result.exit_code == 130
    assert "Guide cancelled" in result.output
    local_guide.assert_not_called()


def test_guide_quotes_apostrophe_in_profile(local_guide, monkeypatch):
    monkeypatch.setattr("awsherlock.cli.list_profiles", lambda: [ProfileMetadata("team's profile", None)])
    result = CliRunner().invoke(app, ["guide"], input="1\n\nall\n")
    assert result.exit_code == 0, result.output
    expected = "--profile 'team''s profile'" if sys.platform == "win32" else "--profile 'team'\"'\"'s profile'"
    assert expected in result.output
    local_guide.assert_not_called()
