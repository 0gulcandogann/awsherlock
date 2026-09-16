"""Shared terminal palette and safe informational messages."""

from contextvars import ContextVar
from rich.console import Console as RichConsole
from rich.text import Text
import typer
from awsherlock.branding import terminal_text

ORANGE = "#ff7e55"
PURPLE = "#650f78"
GREEN = "#9dff7a"
YELLOW = "#ffd369"
RED = "#ff0000"
CYAN = "#5bfcfc"
COLOR_MODE: ContextVar[str] = ContextVar("awsherlock_color_mode", default="auto")


class Console(RichConsole):
    """Apply the current invocation's explicit color preference."""

    def __init__(self, **options: object) -> None:
        mode = COLOR_MODE.get()
        if mode == "never":
            options["color_system"] = None
        elif mode == "always":
            options["force_terminal"] = True
            options.setdefault("color_system", "truecolor")
            options.setdefault("legacy_windows", False)
        super().__init__(**options)


def color_option(ctx: typer.Context, value: str | None) -> str | None:
    """Scope terminal and Typer color overrides to this command invocation."""
    if value is None:
        return value
    if value not in {"auto", "always", "never"}:
        raise typer.BadParameter("Use auto, always or never.", param_hint="--color")
    from typer import rich_utils
    token = COLOR_MODE.set(value)
    previous = (rich_utils.FORCE_TERMINAL, rich_utils.COLOR_SYSTEM, rich_utils.Console)
    baseline = ctx.find_root().meta.setdefault("awsherlock_color_baseline", previous)
    if value == "always":
        rich_utils.FORCE_TERMINAL = True
        rich_utils.COLOR_SYSTEM = "truecolor"
        rich_utils.Console = Console
    elif value == "never":
        rich_utils.COLOR_SYSTEM = None
    else:
        rich_utils.FORCE_TERMINAL, rich_utils.COLOR_SYSTEM, rich_utils.Console = baseline
    def restore() -> None:
        COLOR_MODE.reset(token)
        rich_utils.FORCE_TERMINAL, rich_utils.COLOR_SYSTEM, rich_utils.Console = previous
    ctx.call_on_close(restore)
    return value


def message(value: str, *, style: str = CYAN, err: bool = False) -> None:
    """Print literal text, honoring the terminal's color capability and NO_COLOR."""
    Console(stderr=err).print(Text(terminal_text(value, multiline=True), style=style))


def field(label: str, value: str) -> None:
    line = Text(f"{terminal_text(label)}:", style=f"bold {ORANGE}")
    line.append(f" {terminal_text(value)}", style=CYAN)
    Console().print(line)


def configure_typer_styles() -> None:
    """Configure Typer's Rich style constants once when constructing our CLI."""
    from typer import rich_utils
    styles = {
        "STYLE_OPTION": f"bold {CYAN}", "STYLE_SWITCH": f"bold {GREEN}",
        "STYLE_NEGATIVE_OPTION": f"bold {ORANGE}", "STYLE_NEGATIVE_SWITCH": f"bold {ORANGE}",
        "STYLE_TYPES": YELLOW, "STYLE_USAGE": ORANGE, "STYLE_USAGE_COMMAND": f"bold {CYAN}",
        "STYLE_HELPTEXT_FIRST_LINE": CYAN, "STYLE_HELPTEXT": CYAN,
        "STYLE_OPTION_HELP": CYAN, "STYLE_OPTION_DEFAULT": YELLOW,
        "STYLE_OPTION_ENVVAR": YELLOW, "STYLE_REQUIRED_SHORT": RED, "STYLE_REQUIRED_LONG": RED,
        "STYLE_OPTIONS_PANEL_BORDER": PURPLE, "STYLE_COMMANDS_PANEL_BORDER": PURPLE,
        "STYLE_COMMANDS_TABLE_FIRST_COLUMN": f"bold {GREEN}",
        "STYLE_ERRORS_PANEL_BORDER": RED, "STYLE_ERRORS_SUGGESTION": YELLOW,
        "STYLE_ABORTED": RED, "STYLE_DEPRECATED": ORANGE,
    }
    for name, style in styles.items():
        setattr(rich_utils, name, style)
