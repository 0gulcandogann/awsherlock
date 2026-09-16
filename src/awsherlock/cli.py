"""Command-line entry point for AWSherlock."""

from typing import Annotated
from pathlib import Path

import typer

from awsherlock import __version__
from awsherlock.aws.session import SessionError, create_scan_context
from awsherlock.snapshot import SnapshotError, capture_snapshot, read_snapshot, write_snapshot
from awsherlock.scanner import parse_services
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.organization import scan_organization
from awsherlock.reporting import render_console, render_json, render_html, write_report

app = typer.Typer(
    name="awsherlock",
    help="AWSherlock: an open-source AWS security scanner.",
    add_completion=False,
    invoke_without_command=True,
)


def show_version(value: bool) -> None:
    """Print the version before processing commands."""
    if value:
        typer.echo(f"AWSherlock {__version__}")
        raise typer.Exit()


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
) -> None:
    """Provide top-level CLI options."""
    if ctx.invoked_subcommand is None:
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
) -> None:
    """Identify the AWS account, scan selected services, or evaluate an offline snapshot."""
    if output not in {None, "console", "json", "html"}:
        raise typer.BadParameter("Use console, json, or html.", param_hint="--output")
    if report_file is not None and output not in {"json", "html"}:
        raise typer.BadParameter("--report-file requires --output json or html.")
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
        if organization:
            context = create_scan_context(profile=profile, role=role)
            report = scan_organization(context, selected, role_name or "AWSherlockAuditRole", external_id, role_session_name)
        elif snapshot_path is not None:
            snapshot = read_snapshot(snapshot_path)
            if services is not None:
                if any(service not in snapshot.services for service in selected):
                    raise SnapshotError("Selected service is absent from the snapshot")
                snapshot.services = {service: snapshot.services[service] for service in selected}
        else:
            context = create_scan_context(profile=profile, role=role, role_session_name=role_session_name, external_id=external_id)
            snapshot = capture_snapshot(context, selected)
        if not organization:
            report = evaluate_snapshot(snapshot)
        if output == "html":
            destination = report_file or Path("awsherlock-report.html")
            write_report(render_html(report), destination)
            typer.echo(f"HTML report saved: {destination}")
        elif output == "json":
            content = render_json(report)
            if report_file is not None:
                write_report(content, report_file)
                typer.echo(f"JSON report saved: {report_file}")
            else:
                typer.echo(content, nl=False)
        else:
            render_console(report)
        if report.incomplete:
            raise typer.Exit(code=1)
    except (SessionError, SnapshotError) as error:
        typer.echo(f"Error: {error}", err=True)
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
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from None
    except OSError:
        typer.echo("Error: Could not create snapshot file. Check the path; existing files are not overwritten.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"Snapshot saved: {output}")
    if any(result.issues for result in snapshot.services.values()):
        typer.echo("Snapshot has incomplete collection coverage; inspect its issues.", err=True)
        raise typer.Exit(code=1)
