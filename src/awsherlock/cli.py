"""Command-line entry point for AWSherlock."""

from typing import Annotated
from pathlib import Path
import importlib.util
import shutil
import subprocess
import sys
import math
from time import perf_counter
from botocore.config import Config

import typer

from awsherlock import __version__
from awsherlock.activity import scan_activity
from awsherlock.aws.session import SessionError, create_scan_context, validate_region, validate_account_id, verify_account_id
from awsherlock.snapshot import SnapshotError, capture_snapshot, read_snapshot, write_snapshot, snapshot_saver
from awsherlock.scanner import parse_services
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.organization import scan_organization
from awsherlock.reporting import render_console, render_json, render_html, write_report, render_check_description
from awsherlock.branding import terminal_banner, terminal_text
from awsherlock.catalog import check_catalog, describe_check
from awsherlock.diagnostics import runtime_diagnostics
from awsherlock.terminal import CYAN, GREEN, ORANGE, RED, YELLOW, configure_typer_styles, color_option, field, message
from awsherlock.regional import collection_scopes, parse_regions, scan_regions
from awsherlock.selection import parse_check_selection, parse_account_selection

configure_typer_styles()

app = typer.Typer(
    name="awsherlock",
    help="AWSherlock: an open-source AWS security scanner.",
    epilog=(
        "[bold #ff7e55]Quick start[/]\n\n"
        "[#5bfcfc]awsherlock scan[/] - Scan with existing AWS credentials.\n\n"
        "[#5bfcfc]awsherlock scan --profile production[/] - Use your AWS profile.\n\n"
        "[#5bfcfc]awsherlock scan facts.json[/] - Evaluate saved facts offline.\n\n"
        "[#5bfcfc]awsherlock --describe-check AWSH-CT-001[/] - Explain a check offline.\n\n"
        "[bold #ff7e55]All scan options and examples:[/] [#9dff7a]awsherlock scan --help[/]\n\n"
        "[bold #ff7e55]Snapshot options and examples:[/] [#9dff7a]awsherlock snapshot --help[/]\n\n"
        "[#ffd369]Put scan options after scan; snapshot options after snapshot. "
        "Help does not contact AWS. Replace example profiles and account IDs.[/]\n\n"
        "Full reference: https://github.com/0gulcandogann/awsherlock#command-reference"
    ),
    add_completion=False,
    invoke_without_command=True,
)

REPOSITORY_URL = "git+https://github.com/0gulcandogann/awsherlock.git@main"


def request_options(connect_timeout: float | None, read_timeout: float | None,
                    timeout: float | None, expect_account: str | None) -> dict:
    """Validate local input before touching credentials or AWS."""
    if timeout is not None and (connect_timeout is not None or read_timeout is not None):
        raise typer.BadParameter("--timeout cannot be combined with --connect-timeout or --read-timeout.")
    values = {"connect_timeout": timeout if timeout is not None else connect_timeout,
              "read_timeout": timeout if timeout is not None else read_timeout}
    configured = {name: value for name, value in values.items() if value is not None}
    if any(not math.isfinite(value) or not 0 < value <= 3600 for value in configured.values()):
        raise typer.BadParameter("Request timeouts must be finite seconds greater than 0 and at most 3600.")
    try:
        validate_account_id(expect_account)
    except SessionError as error:
        raise typer.BadParameter(str(error), param_hint="--expect-account") from None
    options = {"client_config": Config(**configured)} if configured else {}
    if expect_account is not None:
        options["expect_account"] = expect_account
    return options


def show_version(value: bool) -> None:
    """Print the version before processing commands."""
    if value:
        message(f"AWSherlock {__version__}", style=f"bold {ORANGE}")
        raise typer.Exit()


def update_installation() -> None:
    """Upgrade the current isolated installation from the public main branch."""
    message("Updating AWSherlock from GitHub...")
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
        message("Update failed: pipx or a Python launcher was not found.", style=RED, err=True)
        raise typer.Exit(code=1)
    last_error: Exception | None = None
    for command in commands:
        try:
            subprocess.run(command, check=True)
            message("AWSherlock updated successfully. Run `awsherlock --version` to verify.", style=GREEN)
            return
        except (OSError, subprocess.CalledProcessError) as error:
            last_error = error
    message(f"Update failed: {terminal_text(str(last_error))}", style=RED, err=True)
    raise typer.Exit(code=1)


@app.callback()
def main(
    ctx: typer.Context,
    color: Annotated[str | None, typer.Option("--color", callback=color_option, is_eager=True,
                                            help="Terminal colors: auto, always or never. NO_COLOR is respected.")] = None,
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
    describe_check_id: Annotated[str | None, typer.Option("--describe-check", help="Explain one supported check ID without contacting AWS.")] = None,
) -> None:
    """Provide top-level CLI options."""
    actions = sum((update, doctor, list_checks, list_services, describe_check_id is not None))
    if actions > 1:
        raise typer.BadParameter("Choose only one of --update, --doctor, --list-checks, --list-services or --describe-check.")
    if actions and ctx.invoked_subcommand is not None:
        raise typer.BadParameter("Top-level actions cannot be combined with a command.")
    if describe_check_id is not None:
        details = describe_check(describe_check_id)
        if details is None:
            raise typer.BadParameter("Unknown check ID. Use --list-checks to see supported IDs.",
                                     param_hint="--describe-check")
        render_check_description(details)
        raise typer.Exit()
    if doctor:
        for label, value in runtime_diagnostics().items():
            field(label, value)
        raise typer.Exit()
    if list_checks:
        checks = check_catalog()
        for check_id, service, title in checks:
            message(f"{check_id}  {service:<14}  {title}")
        message(f"\n{len(checks)} supported checks. Configuration indicators; effective access is not determined.", style=YELLOW)
        raise typer.Exit()
    if list_services:
        checks = check_catalog()
        for service in parse_services(None):
            count = sum(entry[1] == service for entry in checks)
            message(f"{service:<14} {count} checks", style=GREEN)
        raise typer.Exit()
    if update:
        update_installation()
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        message(terminal_banner(), style=ORANGE)
        typer.echo(ctx.get_help())


@app.command(epilog=(
    "[bold #ff7e55]Examples[/]\n\n"
    "[#5bfcfc]awsherlock scan --services iam,s3 --summary-only[/]\n\n"
    "[#5bfcfc]awsherlock scan --regions eu-central-1,eu-west-1[/]\n\n"
    "[#5bfcfc]awsherlock scan --save-snapshot facts.json --stats[/]\n\n"
    "[#5bfcfc]awsherlock scan organization --role-name audit/Reader[/]\n\n"
    "[#5bfcfc]awsherlock scan facts.json --output json[/]\n\n"
    "[#5bfcfc]awsherlock scan facts.json --checks AWSH-S3-001[/]\n\n"
    "[#ffd369]Default: all seven services, console output, SDK-configured region. "
    "Use --region OR --regions. --summary-only requires console output. "
    "--report-file requires JSON/HTML. --timeout sets both request limits; "
    "do not combine with separate timeout flags. Offline scans reject AWS "
    "authentication, regions, request timeouts and --save-snapshot. "
    "--accounts is organization-only. --checks selects evaluation, not collection. "
    "Excluded scope stays NOT_SCANNED/PARTIAL and exits 1. "
    "Incomplete coverage exits 1; findings alone do not change exit 0.[/]"
))
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
    region: Annotated[str | None, typer.Option("--region", help="Override the SDK region for live regional services.")] = None,
    regions: Annotated[str | None, typer.Option("--regions", help="Comma-separated live regions; IAM/S3 run once.")] = None,
    expect_account: Annotated[str | None, typer.Option("--expect-account", help="Stop if resolved account differs from this 12-digit ID.")] = None,
    save_snapshot: Annotated[Path | None, typer.Option("--save-snapshot", help="Save a new normalized file, or a new directory for organization/multi-region scans.")] = None,
    connect_timeout: Annotated[float | None, typer.Option("--connect-timeout", help="Socket connection timeout in seconds, greater than 0 and at most 3600.")] = None,
    read_timeout: Annotated[float | None, typer.Option("--read-timeout", help="Socket read timeout in seconds, greater than 0 and at most 3600.")] = None,
    timeout: Annotated[float | None, typer.Option("--timeout", help="Set both request timeouts; not an overall scan deadline.")] = None,
    color: Annotated[str | None, typer.Option("--color", callback=color_option, is_eager=True, help="Terminal colors: auto, always or never.")] = None,
    stats: Annotated[bool, typer.Option("--stats", help="Print measured scan duration and result counts on stderr.")] = False,
    checks: Annotated[str | None, typer.Option("--checks", help="Evaluate comma-separated check IDs; collection is unchanged and exclusions remain visible.")] = None,
    accounts: Annotated[str | None, typer.Option("--accounts", help="Scan only these comma-separated 12-digit organization account IDs; discovery still lists all accounts.")] = None,
) -> None:
    """Identify the AWS account, scan selected services, or evaluate an offline snapshot."""
    if output not in {None, "console", "json", "html"}:
        raise typer.BadParameter("Use console, json, or html.", param_hint="--output")
    if report_file is not None and output not in {"json", "html"}:
        raise typer.BadParameter("--report-file requires --output json or html.")
    if summary_only and output in {"json", "html"}:
        raise typer.BadParameter("--summary-only requires console output.")
    organization = snapshot_path == Path("organization")
    if accounts is not None and not organization:
        raise typer.BadParameter("--accounts requires scan organization.")
    try:
        selected_checks = parse_check_selection(checks)
        selected_accounts = parse_account_selection(accounts)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from None
    selection_options = ({"selected_checks": selected_checks} if selected_checks is not None else {})
    if region is not None and regions is not None:
        raise typer.BadParameter("Choose either --region or --regions.")
    selected_regions = None
    if regions is not None:
        try:
            selected_regions = parse_regions(regions)
        except SessionError:
            raise typer.BadParameter("Use comma-separated valid region names.", param_hint="--regions") from None
        if snapshot_path is not None and not organization:
            raise typer.BadParameter("--regions cannot be used with an offline snapshot.")
    if region is not None:
        try:
            validate_region(region)
        except SessionError as error:
            raise typer.BadParameter(str(error), param_hint="--region") from None
        if snapshot_path is not None and not organization:
            raise typer.BadParameter("--region cannot be used with an offline snapshot.")
    region_options = {"region": selected_regions[0]} if selected_regions is not None else ({"region": region} if region is not None else {})
    extra_options = request_options(connect_timeout, read_timeout, timeout, expect_account)
    if snapshot_path is not None and not organization and any(value is not None for value in (connect_timeout, read_timeout, timeout, save_snapshot)):
        raise typer.BadParameter("Request timeouts and --save-snapshot require a live scan.")
    report_destination = report_file or (Path("awsherlock-report.html") if output == "html" else None)
    if save_snapshot is not None and (save_snapshot.exists() or
                                     (report_destination is not None and save_snapshot.resolve() == report_destination.resolve())):
        raise typer.BadParameter("Snapshot destination must be new and different from --report-file.")
    sink = snapshot_saver(save_snapshot, bundle=organization or selected_regions is not None) if save_snapshot is not None else None
    if role_name is not None and not organization:
        raise typer.BadParameter("--role-name requires scan organization.")
    if snapshot_path is not None and not organization and any(value is not None for value in (profile, role, role_session_name, external_id)):
        raise typer.BadParameter("AWS authentication options cannot be used with an offline snapshot.")
    try:
        selected = parse_services(services)
    except ValueError:
        raise typer.BadParameter("Unsupported service selection.", param_hint="--services") from None
    started = perf_counter()
    if selected_checks is not None:
        services_by_check = {identifier: owner for identifier, owner, _ in check_catalog()}
        if any(services_by_check[identifier] not in selected for identifier in selected_checks):
            raise typer.BadParameter("Selected checks must belong to the --services selection.")
    work_total = (sum(len(names) for _, names in collection_scopes(selected, selected_regions))
                  if selected_regions is not None else len(selected)) + 2
    try:
        with scan_activity(enabled=not no_progress, show_banner=not no_banner, verbose=verbose) as activity:
            if organization:
                context = create_scan_context(profile=profile, role=role, **region_options, **extra_options)
                activity("Discovering accounts", 0, 1)
                def account_progress(stage: str, completed: int, total: int) -> None:
                    activity(stage, completed + 1 if completed else 0, total + 1)
                report = scan_organization(
                    context, selected, role_name or "AWSherlockAuditRole", external_id,
                    role_session_name, progress=account_progress,
                    **selection_options,
                    **({"selected_accounts": selected_accounts} if selected_accounts is not None else {}),
                    **({"regions": selected_regions} if selected_regions is not None else {}),
                    **({"snapshot_sink": sink} if sink is not None else {}),
                )
            elif snapshot_path is not None:
                activity("Reading snapshot", 0, 2)
                snapshot = read_snapshot(snapshot_path)
                verify_account_id(snapshot.metadata.account_id, expect_account)
                if services is not None:
                    if any(service not in snapshot.services for service in selected):
                        raise SnapshotError("Selected service is absent from the snapshot")
                    snapshot.services = {service: snapshot.services[service] for service in selected}
                activity("Evaluating security checks", 1, 2)
                if selected_checks is not None and any(services_by_check[identifier] not in snapshot.services for identifier in selected_checks):
                    raise SnapshotError("Selected checks are absent from the snapshot")
            else:
                activity("Connecting to AWS", 0, work_total)
                context = create_scan_context(profile=profile, role=role, role_session_name=role_session_name, external_id=external_id, **region_options, **extra_options)
                activity("Collecting AWS resources", 1, work_total)
                def service_progress(stage: str, completed: int, total: int) -> None:
                    activity(stage, completed + 1, total + 2)
                if selected_regions is not None:
                    def regional_progress(stage: str, completed: int, total: int) -> None:
                        activity(stage, completed + 1, total + 1)
                    report = scan_regions(context, selected, selected_regions,
                                          progress=regional_progress, snapshot_sink=sink, **selection_options)
                else:
                    snapshot = capture_snapshot(context, selected, progress=service_progress)
                    if sink is not None:
                        sink(snapshot, context.region or "global")
                    activity("Evaluating security checks", len(selected) + 1, len(selected) + 2)
            if not organization and selected_regions is None:
                report = evaluate_snapshot(snapshot, **selection_options)
            activity("Scan finished - incomplete coverage" if report.incomplete else "Scan finished", 1, 1)
        if output == "html":
            destination = report_file or Path("awsherlock-report.html")
            write_report(render_html(report), destination)
            message(f"HTML report saved: {terminal_text(str(destination))}", style=GREEN)
        elif output == "json":
            content = render_json(report)
            if report_file is not None:
                write_report(content, report_file)
                message(f"JSON report saved: {terminal_text(str(report_file))}", style=GREEN)
            else:
                typer.echo(content, nl=False)
        else:
            if summary_only:
                render_console(report, summary_only=True)
            else:
                render_console(report)
        if save_snapshot is not None:
            if save_snapshot.exists():
                message(f"Snapshots saved: {terminal_text(str(save_snapshot))}", style=GREEN, err=True)
            else:
                message("No snapshots saved: no account collection completed.", style=YELLOW, err=True)
        if stats:
            summary = report.to_dict()["summary"]
            message(f"Stats: {perf_counter() - started:.3f}s elapsed / {summary['resources']} resources / "
                    f"{summary['checks_evaluated']} checks evaluated / {summary['findings']} findings", err=True)
        if report.incomplete:
            raise typer.Exit(code=1)
    except (SessionError, SnapshotError) as error:
        message(f"Error: {terminal_text(str(error))}", style=RED, err=True)
        raise typer.Exit(code=1) from None
    except OSError:
        message("Error: Could not read or create the file. Check paths; existing reports are not overwritten.", style=RED, err=True)
        raise typer.Exit(code=1) from None


@app.command("snapshot", epilog=(
    "[bold #ff7e55]Examples[/]\n\n"
    "[#5bfcfc]awsherlock snapshot --output facts.json[/]\n\n"
    "[#5bfcfc]awsherlock snapshot --output facts.json --services iam,s3[/]\n\n"
    "[#5bfcfc]awsherlock scan facts.json --summary-only[/]\n\n"
    "[#ffd369]--output is a required new JSON file path, not a report format. "
    "Existing files are not overwritten. Default: all seven services and SDK "
    "authentication/region. No security rules run during capture. "
    "--role-session-name and --external-id require --role. "
    "--timeout cannot be combined with separate timeout flags. "
    "For organization/multiple regions, use scan --save-snapshot instead.[/]"
))
def snapshot_command(
    output: Annotated[Path, typer.Option("--output", help="New snapshot JSON file.")],
    services: Annotated[str | None, typer.Option("--services", help="Comma-separated supported services (default: all seven). See --list-services.")] = None,
    profile: Annotated[str | None, typer.Option("--profile", help="Use a named AWS SDK profile; otherwise use the standard credential chain.")] = None,
    role: Annotated[str | None, typer.Option("--role", help="Assume this IAM role before collecting facts.")] = None,
    role_session_name: Annotated[str | None, typer.Option("--role-session-name", help="Assumed-role session name (default: AWSherlock); requires --role.")] = None,
    external_id: Annotated[str | None, typer.Option("--external-id", help="External ID required by the role trust policy; requires --role.")] = None,
    region: Annotated[str | None, typer.Option("--region", help="Override the SDK region.")] = None,
    expect_account: Annotated[str | None, typer.Option("--expect-account", help="Required 12-digit AWS account ID.")] = None,
    connect_timeout: Annotated[float | None, typer.Option("--connect-timeout", help="Socket connection timeout in seconds.")] = None,
    read_timeout: Annotated[float | None, typer.Option("--read-timeout", help="Socket read timeout in seconds.")] = None,
    timeout: Annotated[float | None, typer.Option("--timeout", help="Set both request timeouts.")] = None,
    color: Annotated[str | None, typer.Option("--color", callback=color_option, is_eager=True, help="Terminal colors: auto, always or never.")] = None,
) -> None:
    """Collect normalized AWS facts without running security rules."""
    try:
        selected = parse_services(services)
    except ValueError:
        raise typer.BadParameter("Unsupported service selection.", param_hint="--services") from None
    options = request_options(connect_timeout, read_timeout, timeout, expect_account)
    if region is not None:
        try:
            validate_region(region)
        except SessionError as error:
            raise typer.BadParameter(str(error), param_hint="--region") from None
        options["region"] = region
    try:
        context = create_scan_context(profile=profile, role=role, role_session_name=role_session_name, external_id=external_id, **options)
        snapshot = capture_snapshot(context, selected)
        write_snapshot(snapshot, output)
    except (SessionError, SnapshotError) as error:
        message(f"Error: {terminal_text(str(error))}", style=RED, err=True)
        raise typer.Exit(code=1) from None
    except OSError:
        message("Error: Could not create snapshot file. Check the path; existing files are not overwritten.", style=RED, err=True)
        raise typer.Exit(code=1) from None
    message(terminal_banner(), style=ORANGE)
    message(f"Snapshot saved: {terminal_text(str(output))}", style=GREEN)
    if any(result.issues for result in snapshot.services.values()):
        message("Snapshot has incomplete collection coverage; inspect its issues.", style=YELLOW, err=True)
        raise typer.Exit(code=1)
