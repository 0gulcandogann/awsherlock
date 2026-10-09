"""Description styling preserves readable text and terminal capability handling."""

from io import StringIO

import pytest
from rich.console import Console

from awsherlock.catalog import describe_check
from awsherlock.reporting import render_check_description


@pytest.mark.parametrize("terminal,no_color", [(False, False), (True, False), (True, True)])
def test_palette_and_plain_output(monkeypatch, terminal, no_color):
    stream = StringIO()
    console = Console(file=stream, force_terminal=terminal, color_system="truecolor" if terminal else "auto",
                      no_color=no_color, width=200, legacy_windows=False,
                      _environ={"TERM": "xterm"})
    monkeypatch.setattr("awsherlock.reporting.Console", lambda **kwargs: console)
    details = describe_check("AWSH-CT-001")
    render_check_description(details)
    output = stream.getvalue()
    if terminal and not no_color:
        for rgb in ("255;126;85", "101;15;120", "157;255;122",
                    "255;211;105", "255;0;0", "91;252;252"):
            assert rgb in output
    elif not terminal:
        assert "\x1b" not in output
        assert output == "".join(f"{label}: {value}\n" for label, value in details.items())
    else:
        assert "38;2;" not in output and "48;2;" not in output


def test_description_literals_and_controls_are_safe(monkeypatch):
    stream = StringIO()
    monkeypatch.setattr("awsherlock.reporting.Console", lambda **kwargs: Console(
        file=stream, width=200, color_system=None))
    render_check_description({"Title": "[red]literal[/red]\x1b[2J", "Scope": "warning\rFAKE"})
    assert "[red]literal[/red]\\x1b[2J" in stream.getvalue()
    assert "warning\\rFAKE" in stream.getvalue()
    assert "\x1b" not in stream.getvalue()
