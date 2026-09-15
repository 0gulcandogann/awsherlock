"""Command-line entry point for AWSherlock."""

from typing import Annotated

import typer
from rich.console import Console

from awsherlock import __version__
from awsherlock.aws.session import SessionError, create_scan_context

app = typer.Typer(
    name="awsherlock",
    help="AWSherlock: an open-source AWS security scanner.",
    add_completion=False,
)


def show_version(value: bool) -> None:
    """Print the version before processing commands."""
    if value:
        typer.echo(f"AWSherlock {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=show_version,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Provide top-level CLI options."""


@app.command()
def scan(
    profile: Annotated[
        str | None, typer.Option("--profile", help="Use a named AWS SDK profile.")
    ] = None,
) -> None:
    """Identify the AWS account; security scanning is not implemented yet."""
    try:
        context = create_scan_context(profile=profile)
    except SessionError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from None

    console = Console()
    console.print(f"Account: {context.account_id}", markup=False)
    console.print(f"Caller ARN: {context.caller_arn}", markup=False)
    console.print(f"Partition: {context.partition}", markup=False)
    console.print(f"Profile: {context.profile or 'default credential chain'}", markup=False)
    console.print(f"Region: {context.region or 'not configured'}", markup=False)
    console.print("Security scanning is not implemented yet. No security checks were run.")
