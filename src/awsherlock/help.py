"""Root usage examples share the CLI's boxed help layout."""

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typer.core import TyperGroup

from awsherlock.terminal import Console, CYAN, GREEN, ORANGE, PURPLE, YELLOW


class RootHelpGroup(TyperGroup):
    def format_help(self, ctx, formatter) -> None:
        super().format_help(ctx, formatter)
        console = Console()
        table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
        table.add_column(style=GREEN, ratio=1)
        table.add_column(style=CYAN, ratio=1)
        for command, description in (
            ("awsherlock profiles list", "List local profiles; no AWS calls."),
            ("awsherlock guide", "Choose profile, region and services locally."),
            ("awsherlock whoami --profile production", "Verify the effective account and principal live."),
            ("awsherlock scan", "Scan with existing AWS credentials."),
            ("awsherlock scan --profile production", "Use your AWS profile."),
            ("awsherlock scan --preview", "Inspect a local plan without AWS calls."),
            ("awsherlock scan facts.json", "Evaluate saved facts offline."),
            ("awsherlock --describe-check AWSH-CT-001", "Explain a check offline."),
            ("awsherlock --update", "Update from GitHub main; internet required."),
            ("awsherlock --version", "Verify the installed version after updating."),
            ("awsherlock scan --help", "All scan options and examples."),
            ("awsherlock snapshot --help", "Snapshot options and examples."),
        ):
            table.add_row(command, description)
        notes = Text(
            "\nPut scan options after scan; snapshot options after snapshot. "
            "Help does not contact AWS. Replace example profiles and account IDs.\n\n"
            "Clone-based pipx install unchanged? Pull the clone and reinstall.\n"
            "https://github.com/0gulcandogann/awsherlock#update-or-remove\n\n"
            "Full reference: https://github.com/0gulcandogann/awsherlock#command-reference",
            style=YELLOW,
        )
        console.print(Panel(Group(table, notes), title=Text("Quick start", style=f"bold {ORANGE}"),
                            title_align="left", border_style=PURPLE, box=box.ROUNDED))
