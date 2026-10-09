"""Scan help stays local and groups the existing options without changing them."""

import re
from unittest.mock import Mock

import typer
from typer.testing import CliRunner

from awsherlock.cli import app


PANELS = {
    "Targets and credentials": {"profile", "role", "role_session_name", "external_id", "role_name",
                                "region", "regions", "expect_account", "accounts", "ous"},
    "Scope and selection": {"services", "checks", "resources", "preview", "preview_format"},
    "Identity evidence": {"identity_governance", "identity_inventory", "identity_events",
                          "identity_ai_services", "identity_analyzers", "identity_days",
                          "identity_max_pages", "identity_max_seconds"},
    "Reports and measurements": {"output", "report_file", "save_snapshot", "measurements_file", "suppressions_file"},
    "Execution and display": {"no_progress", "no_banner", "verbose", "summary_only", "fail_on",
                              "connect_timeout", "read_timeout", "timeout", "max_workers", "color", "stats"},
}


def test_every_scan_option_has_one_expected_help_panel():
    command = typer.main.get_command(app).commands["scan"]
    actual = {panel: {parameter.name for parameter in command.params
                      if parameter.rich_help_panel == panel} for panel in PANELS}
    assert actual == PANELS
    assert {parameter.name for parameter in command.params if parameter.rich_help_panel is None} == {
        "snapshot_path"}


def test_grouped_help_is_local_and_readable_without_color(tmp_path, monkeypatch):
    blocked = Mock(side_effect=AssertionError("Help must stay local"))
    for name in ("create_scan_context", "capture_snapshot", "write_report", "snapshot_saver"):
        monkeypatch.setattr(f"awsherlock.cli.{name}", blocked)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["scan", "--help"], terminal_width=72,
                                env={"NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "72"})
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.output
    for panel in PANELS:
        assert panel in result.output
    for option in ("--profile", "--services", "--identity-events", "--output",
                   "--measurements-file", "--no-progress"):
        assert len(re.findall(rf"^\s*[│|]\s*{option}\s", result.output, re.M)) == 1
    wide = CliRunner().invoke(app, ["scan", "--help"], terminal_width=120,
                              env={"NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "120"})
    assert wide.exit_code == 0 and "--identity-governance" in wide.output
    assert list(tmp_path.iterdir()) == []
    blocked.assert_not_called()
