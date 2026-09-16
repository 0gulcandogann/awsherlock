"""Measured scan progress beneath the terminal identity."""

from collections.abc import Callable, Iterator
from contextlib import contextmanager

from rich.console import Console
from rich.progress import Progress, ProgressColumn, Task, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.text import Text

from awsherlock.branding import terminal_banner, terminal_text

ProgressCallback = Callable[[str, int, int], None]


class ASCIIBarColumn(ProgressColumn):
    """Fill a bar with portable ASCII characters, including partial progress."""

    def render(self, task: Task) -> Text:
        filled = min(20, max(0, int(task.percentage / 5)))
        return Text("[" + "#" * filled + "-" * (20 - filled) + "]", style="cyan")


@contextmanager
def scan_activity() -> Iterator[ProgressCallback]:
    """Show completed work units on stderr without changing terminal screens."""
    console = Console(stderr=True)
    interactive = console.is_terminal and not console.is_dumb_terminal
    if interactive:
        console.print(terminal_banner(width=console.width, encoding=getattr(console.file, "encoding", None)),
                      markup=False, highlight=False, soft_wrap=True)
    with Progress(
        TextColumn("{task.description}"),
        ASCIIBarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        disable=not interactive,
        refresh_per_second=4,
        redirect_stdout=False,
        redirect_stderr=False,
    ) as progress:
        task = progress.add_task("Connecting to AWS", total=1)

        def update(stage: str, completed: int, total: int) -> None:
            progress.update(task, description=terminal_text(stage), completed=completed, total=total)
            if interactive:
                progress.refresh()

        yield update
