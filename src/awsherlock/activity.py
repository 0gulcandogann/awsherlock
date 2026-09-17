"""Measured scan progress beneath the terminal identity."""

from collections.abc import Callable, Iterator
from contextlib import contextmanager

from rich.progress import Progress, ProgressColumn, SpinnerColumn, Task, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.text import Text

from awsherlock.branding import terminal_banner, terminal_text
from awsherlock.terminal import CYAN, GREEN, ORANGE, YELLOW, Console, COLOR_MODE

ProgressCallback = Callable[[str, int, int], None]


@contextmanager
def update_activity() -> Iterator[tuple[Callable[[str], None], bool]]:
    """Animate real update work without inventing download percentages."""
    console = Console(stderr=True)
    interactive = console.is_terminal and not console.is_dumb_terminal
    if COLOR_MODE.get() == "always" and not getattr(console.file, "isatty", lambda: False)():
        interactive = False
    with Progress(
        SpinnerColumn(spinner_name="line", style=ORANGE),
        TextColumn("{task.description}", style=CYAN),
        PaletteElapsedColumn(),
        console=console,
        disable=not interactive,
        transient=True,
        refresh_per_second=10,
        redirect_stdout=False,
        redirect_stderr=False,
    ) as progress:
        task = progress.add_task("Preparing update", total=None)

        def stage(description: str) -> None:
            progress.update(task, description=terminal_text(description), refresh=interactive)

        yield stage, interactive


class ASCIIBarColumn(ProgressColumn):
    """Fill a bar with portable ASCII characters, including partial progress."""

    def render(self, task: Task) -> Text:
        filled = min(20, max(0, int(task.percentage / 5)))
        return Text("[" + "#" * filled + "-" * (20 - filled) + "]", style=GREEN)


class PaletteElapsedColumn(TimeElapsedColumn):
    """Retain Rich's elapsed-time calculation with the shared palette."""

    def render(self, task: Task) -> Text:
        text = super().render(task)
        text.style = YELLOW
        return text


@contextmanager
def scan_activity(*, enabled: bool = True, show_banner: bool = True,
                  verbose: bool = False) -> Iterator[ProgressCallback]:
    """Show completed work units on stderr without changing terminal screens."""
    console = Console(stderr=True)
    interactive = enabled and console.is_terminal and not console.is_dumb_terminal
    if COLOR_MODE.get() == "always" and not getattr(console.file, "isatty", lambda: False)():
        interactive = False
    if interactive and show_banner:
        console.print(terminal_banner(width=console.width, encoding=getattr(console.file, "encoding", None)),
                      style=ORANGE, markup=False, highlight=False, soft_wrap=True)
    with Progress(
        TextColumn("{task.description}", style=CYAN),
        ASCIIBarColumn(),
        TaskProgressColumn(text_format=f"[{GREEN}]{{task.percentage:>3.0f}}%"),
        PaletteElapsedColumn(),
        console=console,
        disable=not interactive,
        refresh_per_second=4,
        redirect_stdout=False,
        redirect_stderr=False,
    ) as progress:
        task = progress.add_task("Connecting to AWS", total=1)

        def update(stage: str, completed: int, total: int) -> None:
            progress.update(task, description=terminal_text(stage), completed=completed, total=total)
            if verbose:
                console.print(f"[scan] {terminal_text(stage)} ({completed}/{total} work units)",
                              style=YELLOW, markup=False, highlight=False)
            if interactive:
                progress.refresh()

        yield update
