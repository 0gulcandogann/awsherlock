"""Command-line entry point for AWSherlock."""

from typing import Annotated
from pathlib import Path
import importlib.util
import shutil
import subprocess
import sys

import typer

from awsherlock import __version__
from awsherlock.activity import scan_activity
from awsherlock.aws.session import SessionError, create_scan_context
from awsherlock.snapshot import SnapshotError, capture_snapshot, read_snapshot, write_snapshot
from awsherlock.scanner import parse_services
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.organization import scan_organization
from awsherlock.reporting import render_console, render_json, render_html, write_report
from awsherlock.branding import terminal_banner, terminal_text
from awsherlock.catalog import check_catalog
from awsherlock.diagnostics import runtime_diagnostics

app = typer.Typer(
    name="awsherlock",
    help="AWSherlock: an open-source AWS security scanner.",
    add_completion=False,
    invoke_without_command=True,
)

REPOSITORY_URL = "git+https://github.com/0gulcandogann/awsherlock.git@main"


def show_version(value: bool) -> None:
    """Print the version before processing commands."""
    if value:
        typer.echo(f"AWSherlock {__version__}")
        raise typer.Exit()


def update_installation() -> None:
    """Upgrade the current isolated installation from the public main branch."""
    typer.echo("Updating AWSherlock from GitHub...")
    commands: list[list[str]] = []
    if importlib.util.find_spec("pip") is not None:
        commands.append([sys.executable, "-m", "pip", "install", "--upgrade", REPOSITORY_URL])
    pipx = shutil.which("pipx")
    if pipx:
        commands.append([pipx, "upgrade", "awsherlock"])
    launcher = shutil.which("py") or shutil.which("python3") or shutil.which("python")
    if launcher:
        commands.append([launcher, "-m", "pipx", "upgrade", "awsherlock"])
    if not commands:
        typer.echo("Update failed: pipx or a Python launcher was not found.", err=True)
        raise typer.Exit(code=1)
    last_error: Exception | None = None
    for command in commands:
        try:
            subprocess.run(command, check=True)
            typer.echo("AWSherlock updated successfully. Run `awsherlock --version` to verify.")
            return
        except (OSError, subprocess.CalledProcessError) as error:
            last_error = error
    typer.echo(f"Update failed: {terminal_text(str(last_error))}", err=True)
    raise typer.Exit(code=1)


@app.callback()
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=show_version,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
    update: Annotated[
        bool,
        typer.Option(
            "--update",
            help="Update this installation from the latest GitHub main branch.",
        ),
    ] = False,
    doctor: Annotated[bool, typer.Option("--doctor", help="Show local installation and terminal diagnostics; no AWS calls.")] = False,
    list_checks: Annotated[bool, typer.Option("--list-checks", help="List supported checks without contacting AWS.")] = False,
    list_services: Annotated[bool, typer.Option("--list-services", help="List supported services and check counts; no AWS calls.")] = False,
) -> None:
    """Provide top-level CLI options."""
    actions = sum((update, doctor, list_checks, list_services))
    if actions > 1:
        raise typer.BadParameter("Choose only one of --update, --doctor, --list-checks or --list-services.")
    if actions and ctx.invoked_subcommand is not None:
        raise typer.BadParameter("Top-level actions cannot be combined with a command.")
    if doctor:
        for label, value in runtime_diagnostics().items():
            typer.echo(f"{label}: {terminal_text(value)}")
        raise typer.Exit()
    if list_checks:
        checks = check_catalog()
        for check_id, service, title in checks:
            typer.echo(f"{check_id}  {service:<14}  {title}")
        typer.echo(f"\n{len(checks)} supported checks. Configuration indicators; effective access is not determined.")
        raise typer.Exit()
    if list_services:
        checks = check_catalog()
        for service in parse_services(None):
            count = sum(entry[1] == service for entry in checks)
            typer.echo(f"{service:<14} {count} checks")
        raise typer.Exit()
    if update:
        update_installation()
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(terminal_banner())
        typer.echo(ctx.get_help())


@app.command()
def scan(
    snapshot_path: Annotated[Path | None, typer.Argument(help="Offline snapshot JSON, or 'organization' for multi-account scanning.")] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Use a named AWS SDK profile.")
    ] = None,
    role: Annotated[
        str | None, typer.Option("--role", help="Assume this IAM role before resolving identity.")
    ] = None,
    role_session_name: Annotated[
        str | None, typer.Option("--role-session-name", help="Role session name (default: AWSherlock).")
    ] = None,
    external_id: Annotated[
        str | None, typer.Option("--external-id", help="External ID required by the role trust policy.")
    ] = None,
    services: Annotated[
        str | None, typer.Option("--services", help="Comma-separated services: iam,s3,ec2,lambda,secretsmanager,cloudtrail,kms.")
    ] = None,
    output: Annotated[str | None, typer.Option("--output", help="Report format: console, json, or html.")] = None,
    report_file: Annotated[Path | None, typer.Option("--report-file", help="Write a report to a new file.")] = None,
    role_name: Annotated[str | None, typer.Option("--role-name", help="Organization target role name/path (default: AWSherlockAuditRole).")] = None,
    no_progress: Annotated[bool, typer.Option("--no-progress", help="Hide the startup banner and progress bar.")] = False,
    no_banner: Annotated[bool, typer.Option("--no-banner", help="Hide the startup banner while keeping the progress bar.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", help="Show sanitized scan stages on stderr; no SDK payloads.")] = False,
    summary_only: Annotated[bool, typer.Option("--summary-only", help="Console counts and coverage without finding cards.")] = False,
) -> None:
    """Identify the AWS account, scan selected services, or evaluate an offline snapshot."""
    if output not in {None, "console", "json", "html"}:
        raise typer.BadParameter("Use console, json, or html.", param_hint="--output")
    if report_file is not None and output not in {"json", "html"}:
        raise typer.BadParameter("--report-file requires --output json or html.")
    if summary_only and output in {"json", "html"}:
        raise typer.BadParameter("--summary-only requires console output.")
    organization = snapshot_path == Path("organization")
    if role_name is not None and not organization:
        raise typer.BadParameter("--role-name requires scan organization.")
    if snapshot_path is not None and not organization and any(value is not None for value in (profile, role, role_session_name, external_id)):
        raise typer.BadParameter("AWS authentication options cannot be used with an offline snapshot.")
    try:
        selected = parse_services(services)
    except ValueError:
        raise typer.BadParameter("Unsupported service selection.", param_hint="--services") from None
    try:
        with scan_activity(enabled=not no_progress, show_banner=not no_banner, verbose=verbose) as activity:
            if organization:
                context = create_scan_context(profile=profile, role=role)
                activity("Discovering accounts", 0, 1)
                def account_progress(stage: str, completed: int, total: int) -> None:
                    activity(stage, completed + 1 if completed else 0, total + 1)
                report = scan_organization(
                    context, selected, role_name or "AWSherlockAuditRole", external_id,
                    role_session_name, progress=account_progress,
                )
            elif snapshot_path is not None:
                activity("Reading snapshot", 0, 2)
                snapshot = read_snapshot(snapshot_path)
                if services is not None:
                    if any(service not in snapshot.services for service in selected):
                        raise SnapshotError("Selected service is absent from the snapshot")
                    snapshot.services = {service: snapshot.services[service] for service in selected}
                activity("Evaluating security checks", 1, 2)
            else:
                activity("Connecting to AWS", 0, len(selected) + 2)
                context = create_scan_context(profile=profile, role=role, role_session_name=role_session_name, external_id=external_id)
                activity("Collecting AWS resources", 1, len(selected) + 2)
                def service_progress(stage: str, completed: int, total: int) -> None:
                    activity(stage, completed + 1, total + 2)
                snapshot = capture_snapshot(context, selected, progress=service_progress)
                activity("Evaluating security checks", len(selected) + 1, len(selected) + 2)
            if not organization:
                report = evaluate_snapshot(snapshot)
            activity("Scan finished - incomplete coverage" if report.incomplete else "Scan finished", 1, 1)
        if output == "html":
            destination = report_file or Path("awsherlock-report.html")
            write_report(render_html(report), destination)
            typer.echo(f"HTML report saved: {terminal_text(str(destination))}")
        elif output == "json":
            content = render_json(report)
            if report_file is not None:
                write_report(content, report_file)
                typer.echo(f"JSON report saved: {terminal_text(str(report_file))}")
            else:
                typer.echo(content, nl=False)
        else:
            if summary_only:
                render_console(report, summary_only=True)
            else:
                render_console(report)
        if report.incomplete:
            raise typer.Exit(code=1)
    except (SessionError, SnapshotError) as error:
        typer.echo(f"Error: {terminal_text(str(error))}", err=True)
        raise typer.Exit(code=1) from None
    except OSError:
        typer.echo("Error: Could not read or create the file. Check paths; existing reports are not overwritten.", err=True)
        raise typer.Exit(code=1) from None


@app.command("snapshot")
def snapshot_command(
    output: Annotated[Path, typer.Option("--output", help="New snapshot JSON file.")],
    services: Annotated[str | None, typer.Option("--services")] = None,
    profile: Annotated[str | None, typer.Option("--profile")] = None,
    role: Annotated[str | None, typer.Option("--role")] = None,
    role_session_name: Annotated[str | None, typer.Option("--role-session-name")] = None,
    external_id: Annotated[str | None, typer.Option("--external-id")] = None,
) -> None:
    """Collect normalized AWS facts without running security rules."""
    try:
        selected = parse_services(services)
    except ValueError:
        raise typer.BadParameter("Unsupported service selection.", param_hint="--services") from None
    try:
        context = create_scan_context(profile=profile, role=role, role_session_name=role_session_name, external_id=external_id)
        snapshot = capture_snapshot(context, selected)
        write_snapshot(snapshot, output)
    except (SessionError, SnapshotError) as error:
        typer.echo(f"Error: {terminal_text(str(error))}", err=True)
        raise typer.Exit(code=1) from None
    except OSError:
        typer.echo("Error: Could not create snapshot file. Check the path; existing files are not overwritten.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(terminal_banner())
    typer.echo(f"Snapshot saved: {terminal_text(str(output))}")
    if any(result.issues for result in snapshot.services.values()):
        typer.echo("Snapshot has incomplete collection coverage; inspect its issues.", err=True)
        raise typer.Exit(code=1)
