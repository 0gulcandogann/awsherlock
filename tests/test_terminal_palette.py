"""Shared colors work across informational surfaces without affecting report data."""

from io import StringIO
import json

import pytest
from rich.console import Console
from typer.testing import CliRunner

from awsherlock.cli import app
from awsherlock.reporting import render_console
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.snapshot import write_snapshot
from awsherlock.terminal import RED, field, message
from test_snapshot import snapshot


@pytest.mark.parametrize("args", [["--version"], ["--doctor"], ["--list-checks"], ["--list-services"]])
def test_informational_commands_use_palette_and_plain_redirect(monkeypatch, args):
    plain = CliRunner().invoke(app, args)
    assert plain.exit_code == 0 and "\x1b" not in plain.stdout
    stream = StringIO()
    monkeypatch.setattr("awsherlock.terminal.Console", lambda **kwargs: Console(
        file=stream, force_terminal=True, color_system="truecolor", width=200,
        legacy_windows=False, _environ={"TERM": "xterm"}))
    colored = CliRunner().invoke(app, args)
    assert colored.exit_code == 0
    assert "\x1b[38;" in stream.getvalue() or "\x1b[1;38;" in stream.getvalue()


@pytest.mark.parametrize("args", [["--help"], ["scan", "--help"], ["scan", "--output", "invalid"]])
def test_typer_help_and_usage_errors_use_palette(monkeypatch, args):
    from typer import rich_utils
    from rich.style import Style
    Style.parse.cache_clear()
    stream = StringIO()
    monkeypatch.setattr(rich_utils, "Console", lambda **kwargs: Console(
        **{**kwargs, "file": stream, "legacy_windows": False,
           "_environ": {"TERM": "xterm"}, "no_color": False}))
    monkeypatch.setattr(rich_utils, "FORCE_TERMINAL", True)
    monkeypatch.setattr(rich_utils, "COLOR_SYSTEM", "truecolor")
    result = CliRunner().invoke(app, args, color=True)
    assert "38;2;" in stream.getvalue()
    assert "91;252;252" in stream.getvalue()
    assert ("101;15;120" if "--help" in args else "255;0;0") in stream.getvalue()


def test_typer_help_uses_distinct_semantic_styles():
    from typer import rich_utils

    assert rich_utils.OPTIONS_PANEL_TITLE != rich_utils.COMMANDS_PANEL_TITLE
    assert rich_utils.STYLE_USAGE != rich_utils.STYLE_USAGE_COMMAND
    assert rich_utils.STYLE_OPTION != rich_utils.STYLE_TYPES
    assert rich_utils.STYLE_HELPTEXT != rich_utils.STYLE_OPTION_HELP


def test_shared_messages_no_color_and_terminal_escaping(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    stream = StringIO()
    monkeypatch.setattr("awsherlock.terminal.Console", lambda **kwargs: Console(
        file=stream, force_terminal=True, color_system="truecolor", width=200,
        legacy_windows=False, _environ={"TERM": "xterm", "NO_COLOR": "1"}))
    message("failure\x1b[2J", style=RED, err=True)
    field("Launcher", "[red]literal[/red]\rFAKE")
    assert "38;2;" not in stream.getvalue() and "48;2;" not in stream.getvalue()
    assert "failure\\x1b[2J" in stream.getvalue()
    assert "[red]literal[/red]\\rFAKE" in stream.getvalue()


def test_scan_console_palette_preserves_denied_coverage(snapshot, monkeypatch):
    stdout, stderr = StringIO(), StringIO()
    monkeypatch.setattr("awsherlock.reporting.Console", lambda **kwargs: Console(
        file=stderr if kwargs.get("stderr") else stdout, force_terminal=True,
        color_system="truecolor", width=200, legacy_windows=False, _environ={"TERM": "xterm"}))
    report = evaluate_snapshot(snapshot)
    before = report.to_dict()
    render_console(report)
    assert "255;126;85" in stdout.getvalue() and "101;15;120" in stdout.getvalue()
    assert "157;255;122" in stdout.getvalue()
    assert "AccessDenied" in stderr.getvalue() and "255;0;0" in stderr.getvalue()
    assert report.to_dict() == before


def test_json_stdout_is_unstyled_with_palette(snapshot, tmp_path):
    path = tmp_path / "snapshot.json"
    write_snapshot(snapshot, path)
    result = CliRunner().invoke(app, ["scan", str(path), "--output", "json", "--no-progress"], color=True)
    assert result.exit_code == 1 and "\x1b" not in result.stdout
    assert json.loads(result.stdout) == evaluate_snapshot(snapshot).to_dict()
