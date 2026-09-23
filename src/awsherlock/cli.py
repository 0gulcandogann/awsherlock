"""Command-line entry point for AWSherlock."""

from typing import Annotated
from pathlib import Path
from contextlib import nullcontext
import importlib.util
import json
import shutil
import subprocess
import sys
import math
import shlex
from dataclasses import replace
from time import perf_counter
from botocore.config import Config

import typer

from awsherlock import __version__
from awsherlock.activity import scan_activity
from awsherlock.help import RootHelpGroup
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
from awsherlock.selection import parse_check_selection, parse_account_selection, parse_ou_selection, parse_resource_selection
from awsherlock.identity_config import IdentityOptions, read_inventory
from awsherlock.identity_display import show_identity, show_offline_identity, show_profiles
from awsherlock.aws.profiles import list_profiles
from awsherlock.aws.context import ScanContext
from awsherlock.measurement import ScanMeasurements

configure_typer_styles()

app = typer.Typer(
    name="awsherlock",
    help="AWSherlock: an open-source AWS security scanner.",
    cls=RootHelpGroup,
    add_completion=False,
    invoke_without_command=True,
)

REPOSITORY_URL = "git+https://github.com/0gulcandogann/awsherlock.git@main"


def show_session_error(error: SessionError, profile: str | None) -> None:
    message(f"Error: {terminal_text(str(error))}", style=RED, err=True)
    command = None
    if error.recovery == "profiles":
        command = "awsherlock profiles list"
    elif error.recovery in {"sso", "configuration"}:
        command = "aws sso login" if error.recovery == "sso" else "aws configure list"
        if profile is not None:
            if terminal_text(profile) != profile:
                command += " --help"
            else:
                quoted = "'" + profile.replace("'", "''") + "'" if sys.platform == "win32" else shlex.quote(profile)
                command += f" --profile {quoted}"
    if command is not None:
        message(f"Next: {command}", err=True)


@app.command()
def whoami(
    profile: Annotated[str | None, typer.Option("--profile", help="Use a named AWS SDK profile.")] = None,
    role: Annotated[str | None, typer.Option("--role", help="Assume this IAM role before identity verification.")] = None,
    role_session_name: Annotated[str | None, typer.Option("--role-session-name", help="Assumed-role session name (default: AWSherlock).")] = None,
    external_id: Annotated[str | None, typer.Option("--external-id", help="External ID required by the role trust policy.")] = None,
    region: Annotated[str | None, typer.Option("--region", help="Override the SDK region.")] = None,
    expect_account: Annotated[str | None, typer.Option("--expect-account", help="Stop if the verified account differs from this ID.")] = None,
    timeout: Annotated[float | None, typer.Option("--timeout", help="Set socket connect/read timeouts; not an overall deadline.")] = None,
    color: Annotated[str | None, typer.Option("--color", callback=color_option, is_eager=True, help="Terminal colors: auto, always or never.")] = None,
) -> None:
    """Verify the effective AWS account/principal live, without collecting resources."""
    options = request_options(None, None, timeout, expect_account)
    try:
        context = create_scan_context(profile=profile, role=role, role_session_name=role_session_name,
                                      external_id=external_id, **({"region": region} if region is not None else {}),
                                      **options)
    except SessionError as error:
        show_session_error(error, profile)
        raise typer.Exit(code=1) from None
    show_identity(context)
    message("Identity verification does not prove scanner permission coverage.")


profiles_app = typer.Typer(help="Inspect local AWS profile metadata; no AWS calls.", add_completion=False)
app.add_typer(profiles_app, name="profiles")


@profiles_app.command("list")
def profiles_list(
    color: Annotated[str | None, typer.Option("--color", callback=color_option, is_eager=True, help="Terminal colors: auto, always or never.")] = None,
) -> None:
    """List configured profile names and regions without resolving credentials."""
    try:
        profiles = list_profiles()
    except SessionError as error:
        show_session_error(error, None)
        raise typer.Exit(code=1) from None
    show_profiles(profiles)


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
        commands.append([sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall", REPOSITORY_URL])
    pipx = shutil.which("pipx")
    if pipx:
        commands.append([pipx, "upgrade", "awsherlock", "--pip-args=--force-reinstall"])
    launcher = shutil.which("py") or shutil.which("python3") or shutil.which("python")
    if launcher:
        commands.append([launcher, "-m", "pipx", "upgrade", "awsherlock", "--pip-args=--force-reinstall"])
    if not commands:
        message("Update failed: pipx or a Python launcher was not found.", style=RED, err=True)
        raise typer.Exit(code=1)
    last_error: Exception | None = None
    for command in commands:
        try:
            subprocess.run(command, check=True)
        except KeyboardInterrupt:
            message("Update cancelled.", style=YELLOW, err=True)
            raise typer.Exit(code=130) from None
        except (OSError, subprocess.CalledProcessError) as error:
            last_error = error
            continue
        message("AWSherlock updated successfully. Run `awsherlock --version` to verify.", style=GREEN)
        return
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
    "[#5bfcfc]awsherlock scan --preview --profile production[/]\n\n"
    "[#5bfcfc]awsherlock scan --preview --preview-format json[/]\n\n"
    "[#5bfcfc]awsherlock scan --regions eu-central-1,eu-west-1[/]\n\n"
    "[#5bfcfc]awsherlock scan --save-snapshot facts.json --stats[/]\n\n"
    "[#5bfcfc]awsherlock scan organization --role-name audit/Reader[/]\n\n"
    "[#5bfcfc]awsherlock scan facts.json --output json[/]\n\n"
    "[#5bfcfc]awsherlock scan facts.json --checks AWSH-S3-001[/]\n\n"
    "[#5bfcfc]awsherlock scan --services iam --region eu-central-1 --identity-governance[/]\n\n"
    "[#5bfcfc]awsherlock scan --services iam --identity-governance --identity-inventory identities.json --identity-events[/]\n\n"
    "[#ffd369]Default: all seven services, console output, SDK-configured region. "
    "Use --region OR --regions. --summary-only requires console output. "
    "--report-file requires JSON/HTML. --timeout sets both request limits; "
    "do not combine with separate timeout flags. Offline scans reject AWS "
    "authentication, regions, request timeouts, --save-snapshot and --measurements-file. "
    "--accounts and --ous are organization-only. --ous includes descendants and intersects --accounts. --checks and --resources select evaluation, not collection. "
    "--preview validates a local plan without AWS calls or output files; --preview-format json prints a version-1 plan separate from --output. Identity and organization membership remain unverified. "
    "Excluded scope stays NOT_SCANNED/PARTIAL and exits 1. "
    "Identity evidence is opt-in; live governance requires IAM and regions for workload/audit reads. "
    "Saved identity facts replay offline. Missing approvals or evidence remain incomplete. "
    "Incomplete coverage exits 1; findings alone do not change exit 0.[/]"
))
def scan(
    snapshot_path: Annotated[Path | None, typer.Argument(help="Offline snapshot JSON, or 'organization' for multi-account scanning.")] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Use a named AWS SDK profile.", rich_help_panel="Targets and credentials")
    ] = None,
    role: Annotated[
        str | None, typer.Option("--role", help="Assume this IAM role before resolving identity.", rich_help_panel="Targets and credentials")
    ] = None,
    role_session_name: Annotated[
        str | None, typer.Option("--role-session-name", help="Role session name (default: AWSherlock).", rich_help_panel="Targets and credentials")
    ] = None,
    external_id: Annotated[
        str | None, typer.Option("--external-id", help="External ID required by the role trust policy.", rich_help_panel="Targets and credentials")
    ] = None,
    services: Annotated[
        str | None, typer.Option("--services", help="Comma-separated services: iam,s3,ec2,lambda,secretsmanager,cloudtrail,kms.", rich_help_panel="Scope and selection")
    ] = None,
    output: Annotated[str | None, typer.Option("--output", help="Report format: console, json, or html.", rich_help_panel="Reports and measurements")] = None,
    report_file: Annotated[Path | None, typer.Option("--report-file", help="Write a report to a new file.", rich_help_panel="Reports and measurements")] = None,
    role_name: Annotated[str | None, typer.Option("--role-name", help="Organization target role name/path (default: AWSherlockAuditRole).", rich_help_panel="Targets and credentials")] = None,
    no_progress: Annotated[bool, typer.Option("--no-progress", help="Hide the startup banner and progress bar.", rich_help_panel="Execution and display")] = False,
    no_banner: Annotated[bool, typer.Option("--no-banner", help="Hide the startup banner while keeping the progress bar.", rich_help_panel="Execution and display")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", help="Show sanitized scan stages on stderr; no SDK payloads.", rich_help_panel="Execution and display")] = False,
    summary_only: Annotated[bool, typer.Option("--summary-only", help="Console counts and coverage without finding cards.", rich_help_panel="Execution and display")] = False,
    region: Annotated[str | None, typer.Option("--region", help="Override the SDK region for live regional services.", rich_help_panel="Targets and credentials")] = None,
    regions: Annotated[str | None, typer.Option("--regions", help="Comma-separated live regions; IAM/S3 run once.", rich_help_panel="Targets and credentials")] = None,
    expect_account: Annotated[str | None, typer.Option("--expect-account", help="Stop if resolved account differs from this 12-digit ID.", rich_help_panel="Targets and credentials")] = None,
    save_snapshot: Annotated[Path | None, typer.Option("--save-snapshot", help="Save a new normalized file, or a new directory for organization/multi-region scans.", rich_help_panel="Reports and measurements")] = None,
    connect_timeout: Annotated[float | None, typer.Option("--connect-timeout", help="Socket connection timeout in seconds, greater than 0 and at most 3600.", rich_help_panel="Execution and display")] = None,
    read_timeout: Annotated[float | None, typer.Option("--read-timeout", help="Socket read timeout in seconds, greater than 0 and at most 3600.", rich_help_panel="Execution and display")] = None,
    timeout: Annotated[float | None, typer.Option("--timeout", help="Set both request timeouts; not an overall scan deadline.", rich_help_panel="Execution and display")] = None,
    color: Annotated[str | None, typer.Option("--color", callback=color_option, is_eager=True, help="Terminal colors: auto, always or never.", rich_help_panel="Execution and display")] = None,
    stats: Annotated[bool, typer.Option("--stats", help="Print measured scan duration and result counts on stderr.", rich_help_panel="Execution and display")] = False,
    measurements_file: Annotated[Path | None, typer.Option("--measurements-file", help="Write opt-in SDK invocation and collection timing JSON to a new file; live scans only.", rich_help_panel="Reports and measurements")] = None,
    checks: Annotated[str | None, typer.Option("--checks", help="Evaluate comma-separated check IDs; collection is unchanged and exclusions remain visible.", rich_help_panel="Scope and selection")] = None,
    accounts: Annotated[str | None, typer.Option("--accounts", help="Scan only these comma-separated 12-digit organization account IDs; discovery still lists all accounts.", rich_help_panel="Targets and credentials")] = None,
    ous: Annotated[str | None, typer.Option("--ous", help="Organization-only OU IDs including descendants; intersects --accounts. Exclusions remain visible.", rich_help_panel="Targets and credentials")] = None,
    resources: Annotated[str | None, typer.Option("--resources", help="Evaluate exact comma-separated resource IDs/ARNs; collection is unchanged. Exclusions and unmatched IDs remain visible.", rich_help_panel="Scope and selection")] = None,
    preview: Annotated[bool, typer.Option("--preview", help="Show the locally validated scan plan without contacting AWS or creating reports.", rich_help_panel="Scope and selection")] = False,
    preview_format: Annotated[str | None, typer.Option("--preview-format", help="Preview text (default) or version-1 JSON; requires --preview and is separate from --output.", rich_help_panel="Scope and selection")] = None,
    identity_governance: Annotated[bool, typer.Option("--identity-governance", help="Collect/evaluate IAM role and user governance evidence, including workload role bindings.", rich_help_panel="Identity evidence")] = False,
    identity_inventory: Annotated[Path | None, typer.Option("--identity-inventory", help="Version-1 identity approval/declaration JSON; also works offline. Requires --identity-governance.", rich_help_panel="Identity evidence")] = None,
    identity_events: Annotated[bool, typer.Option("--identity-events", help="Read bounded regional CloudTrail identity history; requires --identity-governance and a live scan.", rich_help_panel="Identity evidence")] = False,
    identity_ai_services: Annotated[bool, typer.Option("--identity-ai-services", help="Read Bedrock/AgentCore execution-role metadata; requires live --identity-governance.", rich_help_panel="Identity evidence")] = False,
    identity_analyzers: Annotated[bool, typer.Option("--identity-analyzers", help="Read existing Access Analyzer findings; never creates analyzers. Requires live --identity-governance.", rich_help_panel="Identity evidence")] = False,
    identity_days: Annotated[int, typer.Option("--identity-days", min=1, max=90, help="CloudTrail lookback days (1–90); requires --identity-events.", rich_help_panel="Identity evidence")] = 30,
    identity_max_pages: Annotated[int, typer.Option("--identity-max-pages", min=1, max=1000, help="Page/read budget per optional evidence collector, across requested regions.", rich_help_panel="Identity evidence")] = 20,
    identity_max_seconds: Annotated[int, typer.Option("--identity-max-seconds", min=1, max=3600, help="Time budget between evidence requests; in-flight SDK retries/timeouts may exceed it.", rich_help_panel="Identity evidence")] = 60,
) -> None:
    """Identify the AWS account, scan selected services, or evaluate an offline snapshot."""
    if preview_format not in {None, "text", "json"}:
        raise typer.BadParameter("Use text or json.", param_hint="--preview-format")
    if preview_format is not None and not preview:
        raise typer.BadParameter("--preview-format requires --preview.")
    if output not in {None, "console", "json", "html"}:
        raise typer.BadParameter("Use console, json, or html.", param_hint="--output")
    if report_file is not None and output not in {"json", "html"}:
        raise typer.BadParameter("--report-file requires --output json or html.")
    if summary_only and output in {"json", "html"}:
        raise typer.BadParameter("--summary-only requires console output.")
    organization = snapshot_path == Path("organization")
    offline = snapshot_path is not None and not organization
    if measurements_file is not None and (offline or preview):
        raise typer.BadParameter("--measurements-file requires a live scan without --preview.")
    identity_extra = identity_inventory is not None or identity_events or identity_ai_services or identity_analyzers or identity_max_pages != 20 or identity_max_seconds != 60
    if identity_extra and not identity_governance:
        raise typer.BadParameter("Identity evidence options require --identity-governance.")
    if identity_days != 30 and not identity_events:
        raise typer.BadParameter("--identity-days requires --identity-events.")
    if offline and (identity_events or identity_ai_services or identity_analyzers or identity_max_pages != 20 or identity_max_seconds != 60):
        raise typer.BadParameter("Live identity evidence options cannot be used with offline snapshots; saved evidence is evaluated automatically.")
    try:
        declarations = read_inventory(identity_inventory) if identity_inventory is not None else None
    except ValueError as error:
        raise typer.BadParameter(str(error)) from None
    if accounts is not None and not organization:
        raise typer.BadParameter("--accounts requires scan organization.")
    if ous is not None and not organization:
        raise typer.BadParameter("--ous requires scan organization.")
    try:
        selected_checks = parse_check_selection(checks)
        selected_accounts = parse_account_selection(accounts)
        selected_ous = parse_ou_selection(ous)
        selected_resources = parse_resource_selection(resources)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from None
    selection_options = ({"selected_checks": selected_checks} if selected_checks is not None else {})
    if selected_resources is not None:
        selection_options["selected_resources"] = selected_resources
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
    if measurements_file is not None:
        invalid_destination = (
            not measurements_file.parent.is_dir() or measurements_file.exists() or
            (report_destination is not None and measurements_file.resolve() == report_destination.resolve()) or
            (save_snapshot is not None and measurements_file.resolve() == save_snapshot.resolve())
        )
        if invalid_destination:
            raise typer.BadParameter("Measurement destination needs an existing directory and a new path different from report and snapshot destinations.")
    if save_snapshot is not None and (save_snapshot.exists() or
                                     (report_destination is not None and save_snapshot.resolve() == report_destination.resolve())):
        raise typer.BadParameter("Snapshot destination must be new and different from --report-file.")
    if role_name is not None and not organization:
        raise typer.BadParameter("--role-name requires scan organization.")
    if snapshot_path is not None and not organization and any(value is not None for value in (profile, role, role_session_name, external_id)):
        raise typer.BadParameter("AWS authentication options cannot be used with an offline snapshot.")
    try:
        selected = parse_services(services)
    except ValueError:
        raise typer.BadParameter("Unsupported service selection.", param_hint="--services") from None
    started = perf_counter()
    if identity_governance and not offline and "iam" not in selected:
        raise typer.BadParameter("--identity-governance requires iam in --services.")
    identity_options = IdentityOptions(inventory=declarations, events=identity_events, ai_services=identity_ai_services,
                                       analyzers=identity_analyzers, days=identity_days, max_pages=identity_max_pages,
                                       max_seconds=identity_max_seconds, regions=tuple(selected_regions or ([region] if region else []))) if identity_governance else None
    if offline and identity_governance:
        selection_options["identity_governance"] = True
        if declarations is not None:
            selection_options["identity_inventory"] = declarations
    if selected_checks is not None:
        services_by_check = {identifier: owner for identifier, owner, _ in check_catalog()}
        if any(services_by_check[identifier] not in selected for identifier in selected_checks):
            raise typer.BadParameter("Selected checks must belong to the --services selection.")
    if preview:
        snapshot_metadata = None
        if offline:
            try:
                saved = read_snapshot(snapshot_path)
                verify_account_id(saved.metadata.account_id, expect_account)
                if services is not None and any(service not in saved.services for service in selected):
                    raise SnapshotError("Selected service is absent from the snapshot")
                if selected_checks is not None and any(services_by_check[identifier] not in saved.services
                                                       for identifier in selected_checks):
                    raise SnapshotError("Selected checks are absent from the snapshot")
                snapshot_metadata = saved.metadata
            except (SnapshotError, SessionError) as error:
                message(f"Error: {error}", style=RED, err=True)
                raise typer.Exit(code=1) from None
            except OSError:
                message("Error: Could not read the snapshot file. Check the path.", style=RED, err=True)
                raise typer.Exit(code=1) from None
        if preview_format == "json":
            plan = {
                "schema_version": 1, "kind": "scan-preview",
                "mode": "organization" if organization else "offline" if offline else "single-account",
                "verification": {
                    "identity": "snapshot_metadata" if offline else "unverified",
                    "organization_membership": "not_discovered" if organization else None,
                },
                "target": {
                    "profile": None if offline else profile,
                    "source_role": None if offline else role,
                    "expected_account": expect_account,
                    "snapshot_path": str(snapshot_path) if offline else None,
                    "snapshot_account": snapshot_metadata.account_id if offline else None,
                    "snapshot_region": snapshot_metadata.region if offline else None,
                    "regions": ([snapshot_metadata.region] if snapshot_metadata.region else None) if offline else
                               selected_regions if selected_regions is not None else [region] if region else None,
                    "region_source": "snapshot_metadata" if offline else "explicit" if selected_regions is not None or region else "sdk_default",
                    "organization_role_name": (role_name or "AWSherlockAuditRole") if organization else None,
                    "accounts": selected_accounts if organization else None,
                    "ous": selected_ous if organization else None,
                },
                "collection": {"services": selected if services is not None or not offline else list(saved.services)},
                "evaluation": {"checks": selected_checks, "resources": selected_resources,
                               "selectors_affect_collection": False},
                "destinations": {"report_format": output or "console",
                                 "report_file": str(report_destination) if report_destination else None,
                                 "snapshot": str(save_snapshot) if save_snapshot else None},
                "options": {"external_id_supplied": external_id is not None,
                            "identity_governance_requested": identity_governance,
                            "request_timeouts_configured": any(value is not None for value in
                                                               (connect_timeout, read_timeout, timeout))},
            }
            typer.echo(json.dumps(plan, indent=2, ensure_ascii=True, allow_nan=False))
            return
        message("Scan preview: no AWS calls or output files")
        message(f"Mode: {'organization' if organization else 'offline snapshot' if offline else 'single account'}")
        if offline:
            message(f"Snapshot: {snapshot_path}")
            message(f"Snapshot account: {snapshot_metadata.account_id}")
            message(f"Snapshot region: {snapshot_metadata.region or 'unknown'}")
            message("Identity: saved snapshot metadata; no live verification")
        else:
            message(f"Profile: {profile or 'SDK default chain (unverified)'}")
            message(f"Source role: {role or 'none'}")
            message(f"Expected account: {expect_account or 'not supplied'} (unverified)")
            message("Identity and credential availability: unverified")
            message(f"Regions: {', '.join(selected_regions) if selected_regions else region or 'SDK default (unverified)'}")
            if organization:
                message(f"Target role: {role_name or 'AWSherlockAuditRole'}")
                message(f"Requested accounts: {', '.join(selected_accounts) if selected_accounts else 'all discovered accounts (unknown)'}")
                message(f"Requested OUs: {', '.join(selected_ous) if selected_ous else 'none'}")
                message("Organization membership and target identities: not discovered")
        message(f"Services: {', '.join(selected) if services is not None or not offline else ', '.join(saved.services)}")
        message(f"Checks for evaluation: {', '.join(selected_checks) if selected_checks else 'all available for selected services'}")
        message(f"Resources for evaluation: {', '.join(selected_resources) if selected_resources else 'all collected resources'}")
        message("Checks and resources restrict evaluation; collection scope is unchanged.")
        message(f"Report: {output or 'console'}" + (f" -> {report_destination}" if report_destination else " -> terminal"))
        message(f"Snapshot destination: {save_snapshot or 'none'} (no file created)")
        if identity_governance:
            message("Identity governance: selected; evidence availability unverified")
        if any(value is not None for value in (connect_timeout, read_timeout, timeout)):
            message("Request timeouts: configured per SDK request; no overall scan deadline")
        if external_id is not None:
            message("External ID: supplied, value hidden")
        return
    sink = snapshot_saver(save_snapshot, bundle=organization or selected_regions is not None) if save_snapshot is not None else None
    work_total = (sum(len(names) for _, names in collection_scopes(selected, selected_regions))
                  if selected_regions is not None else len(selected)) + 2
    measurements = ScanMeasurements() if measurements_file is not None else None
    try:
        measurement_scope = measurements if measurements is not None else nullcontext()
        with measurement_scope, scan_activity(enabled=not no_progress, show_banner=not no_banner, verbose=verbose) as activity:
            if organization:
                context = create_scan_context(profile=profile, role=role, **region_options, **extra_options)
                if measurements is not None:
                    context = replace(context, measurements=measurements)
                if identity_options is not None:
                    context = replace(context, identity_options=identity_options)
                activity("Discovering accounts", 0, 1)
                show_identity(context, err=True, regions=selected_regions, purpose="organization discovery")
                def target_identity(target: ScanContext) -> None:
                    show_identity(target, err=True, regions=selected_regions, services=selected,
                                  purpose="organization target")
                def account_progress(stage: str, completed: int, total: int) -> None:
                    activity(stage, completed + 1 if completed else 0, total + 1)
                report = scan_organization(
                    context, selected, role_name or "AWSherlockAuditRole", external_id,
                    role_session_name, progress=account_progress,
                    identity_callback=target_identity,
                    **selection_options,
                    **({"selected_accounts": selected_accounts} if selected_accounts is not None else {}),
                    **({"selected_ous": selected_ous} if selected_ous is not None else {}),
                    **({"regions": selected_regions} if selected_regions is not None else {}),
                    **({"snapshot_sink": sink} if sink is not None else {}),
                )
            elif snapshot_path is not None:
                activity("Reading snapshot", 0, 2)
                snapshot = read_snapshot(snapshot_path)
                verify_account_id(snapshot.metadata.account_id, expect_account)
                show_offline_identity(snapshot.metadata.account_id)
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
                if measurements is not None:
                    context = replace(context, measurements=measurements)
                if identity_options is not None:
                    context = replace(context, identity_options=identity_options)
                show_identity(context, err=True, regions=selected_regions, services=selected)
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
        if measurements_file is not None and measurements is not None:
            write_report(json.dumps(measurements.to_dict(), indent=2, allow_nan=False) + "\n", measurements_file)
            message(f"Measurements saved: {terminal_text(str(measurements_file))}", style=GREEN, err=True)
        if stats:
            summary = report.to_dict()["summary"]
            message(f"Stats: {perf_counter() - started:.3f}s elapsed / {summary['resources']} resources / "
                    f"{summary['checks_evaluated']} checks evaluated / {summary['findings']} findings", err=True)
        if report.incomplete:
            raise typer.Exit(code=1)
    except (SessionError, SnapshotError) as error:
        if isinstance(error, SessionError):
            show_session_error(error, profile)
        else:
            message(f"Error: {terminal_text(str(error))}", style=RED, err=True)
        raise typer.Exit(code=1) from None
    except OSError:
        message("Error: Could not read or create the file. Check paths; existing reports are not overwritten.", style=RED, err=True)
        raise typer.Exit(code=1) from None


def _interactive_terminal() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _guide_selection(value: str, count: int, *, multiple: bool = False) -> list[int]:
    parts = [part.strip() for part in value.split(",")]
    if not parts or any(len(part) > 6 or not part.isascii() or not part.isdecimal() or
                        int(part) < (1 if multiple else 0) or int(part) > count for part in parts):
        raise typer.BadParameter("Choose a displayed number" + (" or comma-separated numbers." if multiple else "."))
    if not multiple and len(parts) != 1:
        raise typer.BadParameter("Choose one profile number.")
    return list(dict.fromkeys(int(part) for part in parts))


def _shell_argument(value: str) -> str:
    return "'" + value.replace("'", "''") + "'" if sys.platform == "win32" else shlex.quote(value)


@app.command("guide")
def guide(
    color: Annotated[str | None, typer.Option("--color", callback=color_option, is_eager=True,
                                              help="Terminal colors: auto, always or never.")] = None,
) -> None:
    """Choose a live scan scope locally and print a command to run."""
    if not _interactive_terminal():
        message("Guide needs an interactive terminal. Use awsherlock scan --preview with explicit options.",
                style=RED, err=True)
        raise typer.Exit(code=2)
    try:
        profiles = list_profiles()
    except SessionError as error:
        show_session_error(error, None)
        raise typer.Exit(code=1) from None
    message("0. SDK default credential chain")
    for index, item in enumerate(profiles, 1):
        message(f"{index}. {item.name} (configured region: {item.region or 'unknown'})")
    try:
        profile_number = _guide_selection(typer.prompt("Profile number", default="0"), len(profiles))[0]
        profile = profiles[profile_number - 1].name if profile_number else None
        if profile is not None and terminal_text(profile) != profile:
            raise typer.BadParameter("Selected profile contains terminal control characters.")
        region = typer.prompt("Region override (blank uses SDK configuration)", default="", show_default=False).strip()
        if region:
            try:
                validate_region(region)
            except SessionError as error:
                raise typer.BadParameter(str(error), param_hint="region") from None
        supported_services = parse_services(None)
        for index, service in enumerate(supported_services, 1):
            message(f"{index}. {service}")
        choice = typer.prompt("Services (all or comma-separated numbers)", default="all").strip().lower()
        services = None if choice == "all" else ",".join(supported_services[index - 1]
                                                     for index in _guide_selection(choice, len(supported_services), multiple=True))
    except (KeyboardInterrupt, EOFError, typer.Abort):
        message("Guide cancelled.", style=YELLOW, err=True)
        raise typer.Exit(code=130) from None
    scan(profile=profile, region=region or None, services=services, preview=True)
    command = "awsherlock scan"
    for flag, value in (("--profile", profile), ("--region", region or None), ("--services", services)):
        if value is not None:
            command += f" {flag} {_shell_argument(value)}"
    message("Run this command to scan:")
    typer.echo(terminal_text(command))


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
