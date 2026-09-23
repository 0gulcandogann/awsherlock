"""Console and JSON rendering; reporters never collect or evaluate AWS data."""

import json
from pathlib import Path
from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape
from awsherlock.evaluation import Report
from awsherlock.branding import terminal_text
from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from awsherlock.terminal import CYAN, GREEN, ORANGE, PURPLE, RED, YELLOW, Console


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def write_report(content: str, path: Path) -> None:
    with path.open("x", encoding="utf-8") as output:
        output.write(content)


def render_html(report: Report) -> str:
    environment = Environment(loader=PackageLoader("awsherlock", "templates"),
                              autoescape=select_autoescape(default=True), undefined=StrictUndefined)
    data = report.to_dict()
    accounts = sorted({data["metadata"]["account_id"], *(entry["account_id"] for entry in data["metadata"].get("accounts", [])), *(finding["account_id"] for finding in data["findings"])})
    services = sorted({entry["service"] for entry in data["coverage"]})
    return environment.get_template("report.html").render(report=data, accounts=accounts, services=services)


SEVERITY_STYLES = {"CRITICAL": f"bold {RED}", "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": CYAN, "INFO": GREEN}


def render_check_description(details: dict[str, str]) -> None:
    """Style offline check metadata while preserving plain redirected output."""
    console = Console()
    styles = {
        "Check": (f"bold {CYAN} on {PURPLE}", f"bold {CYAN}"),
        "Title": (f"bold {ORANGE}", f"bold {ORANGE}"),
        "Service": (f"bold {CYAN}", CYAN),
        "Required fact": (f"bold {YELLOW}", YELLOW),
        "Remediation": (f"bold {GREEN}", GREEN),
        "Scope": (f"bold {RED}", YELLOW),
    }
    for label, value in details.items():
        label_style, value_style = styles.get(label, ("bold", "default"))
        line = Text()
        line.append(f"{terminal_text(label)}:", style=label_style)
        line.append(f" {terminal_text(value)}", style=value_style)
        console.print(line)


def render_console(report: Report, *, summary_only: bool = False) -> None:
    console = Console()
    errors = Console(stderr=True)
    data = report.to_dict()
    summary = data["summary"]
    console.print()
    console.print("AWSherlock / Scan results", style=f"bold {ORANGE}", markup=False)
    console.print(f"Account: {terminal_text(report.metadata['account_id'])}", style=CYAN, markup=False)
    region_label = ", ".join(report.metadata["regions"]) if "regions" in report.metadata else (report.metadata.get("region") or "Global / not configured")
    console.print(f"Region: {terminal_text(region_label)}", style=CYAN, markup=False)
    console.print()
    console.print(
        f"{summary['findings']} findings   /   {summary['resources']} resources   /   "
        f"{summary['checks_evaluated']} checks evaluated", style=f"bold {CYAN}", markup=False,
    )
    severity_line = Text()
    for severity, count in summary["severity"].items():
        severity_line.append(f"{severity} {count}   ", style=SEVERITY_STYLES[severity])
    console.print(severity_line)
    if report.suppression_audit is not None:
        console.print(f"Suppressed findings: {summary['suppressed']} / Expired suppression records: {summary['expired_suppressions']}",
                      style=YELLOW)
    if report.incomplete:
        console.print(Panel("Some checks could not run. Review coverage and collection issues below. "
                            "Zero findings do not mean the account is secure.",
                            title="Incomplete scan coverage", border_style=YELLOW, style=YELLOW))
    accounts = report.metadata.get("accounts", [])
    if accounts:
        table = Table(title="Organization accounts", box=box.SIMPLE, expand=True,
                      title_style=f"bold {ORANGE}", header_style=f"bold {YELLOW}", style=CYAN)
        for label in ("Account", "Name", "State", "Scan status"):
            table.add_column(label)
        for account in accounts:
            table.add_row(*(Text(terminal_text(str(account[key]))) for key in ("account_id", "name", "state", "scan_status")))
        console.print(table)
    if report.identities:
        table = Table(title="Identity governance", box=box.SIMPLE, expand=True,
                      title_style=f"bold {ORANGE}", header_style=f"bold {YELLOW}")
        for label in ("Account / identity", "AI attribution", "Approval", "Observed connection", "Scope"):
            table.add_column(label)
        for identity in report.identities:
            values = (identity["account_id"] + " / " + identity["name"], identity["ai_attribution"],
                      identity["approval_status"], ", ".join(identity["observed_mechanisms"]) or "unknown / not observed",
                      identity["evaluation_scope"])
            table.add_row(*(Text(terminal_text(value)) for value in values))
        console.print(table)
    coverage = Table(title="Scan coverage", box=box.SIMPLE, expand=True,
                     title_style=f"bold {ORANGE}", header_style=f"bold {YELLOW}", style=CYAN)
    multi_region = "regions" in report.metadata
    labels = ("Account / Service",) + (("Region / Scope",) if multi_region else ()) + ("Status", "Resources", "Checks", "Not scanned", "Findings")
    for label in labels:
        coverage.add_column(label, justify="right" if label in {"Resources", "Checks", "Not scanned", "Findings"} else "left")
    for entry in report.coverage:
        status_style = GREEN if entry["status"] == "COMPLETE" else YELLOW
        coverage.add_row(Text(f"{terminal_text(entry['account_id'])} / {terminal_text(entry['service'].upper())}"),
                         *((Text(terminal_text(entry.get("region") or entry.get("scope") or "global")),) if multi_region else ()),
                         Text(terminal_text(entry["status"]), style=status_style),
                         *(str(entry[key]) for key in ("resources", "evaluated", "not_scanned", "findings")))
    console.print(coverage)
    rank = {severity: index for index, severity in enumerate(SEVERITY_STYLES)}
    findings = sorted(report.findings, key=lambda finding: rank[finding.severity])
    if not summary_only:
        console.print("Findings", style=f"bold {ORANGE}")
    for index, finding in enumerate([] if summary_only else findings, 1):
        title = Text(f"{index:02d}  {finding.severity}", style=SEVERITY_STYLES[finding.severity])
        body = Text(f"{terminal_text(finding.title)}\n", style=f"bold {ORANGE}")
        body.append(f"{terminal_text(finding.id)} / {terminal_text(finding.service.upper())} / {terminal_text(finding.account_id)}\n", style=CYAN)
        body.append(f"Resource: {terminal_text(finding.resource_id)}\n", style=CYAN)
        body.append(f"{terminal_text(finding.description, multiline=True)}\n\n", style=YELLOW)
        if index - 1 in report.suppression_matches:
            suppression = report.suppression_matches[index - 1]
            body.append("Suppressed until " + terminal_text(suppression["expires_on"]) +
                        " by " + terminal_text(suppression["owner"]) + ": " +
                        terminal_text(suppression["reason"], multiline=True) + "\n\n", style=YELLOW)
        body.append("Remediation: ", style=f"bold {GREEN}")
        body.append(terminal_text(finding.remediation, multiline=True), style=GREEN)
        console.print(Panel(body, title=title, title_align="left", border_style=PURPLE, padding=(1, 2)))
    if not findings:
        console.print("No findings were produced by the evaluated checks. Review scan coverage.", style=YELLOW, markup=False)
    if report.suppression_audit is not None:
        console.print("Suppression audit", style=f"bold {ORANGE}")
        for entry in report.suppression_audit:
            console.print(f"{entry['status']} {terminal_text(entry['check_id'])} / {terminal_text(entry['account_id'])} / "
                          f"{terminal_text(entry['resource_id'])} / expires {terminal_text(entry['expires_on'])} / "
                          f"owner {terminal_text(entry['owner'])} / reason {terminal_text(entry['reason'], multiline=True)}",
                          style=YELLOW, markup=False)
    issues = [(entry, issue) for entry in report.coverage for issue in entry["issues"]]
    if issues:
        has_exclusions = any(issue["operation"] in {"CheckSelection", "AccountSelection", "OUSelection", "ResourceSelection"} for _, issue in issues)
        has_missing_facts = any(issue["operation"] == "RequiredFact" for _, issue in issues)
        errors.print("Scan issues and exclusions" if has_exclusions else "Scan issues" if has_missing_facts else "Collection issues",
                     style=f"bold {RED}")
        for entry, issue in issues:
            label = "NOT_SCANNED" if issue["operation"] in {"CheckSelection", "AccountSelection", "OUSelection", "ResourceSelection", "AccountPublicAccessContext", "RequiredFact"} else "ERROR"
            message = Text(f"{label} {terminal_text(entry['account_id'])} {terminal_text(entry['service'].upper())} / "
                           f"{terminal_text(issue['resource_id'] or 'account')} / {terminal_text(issue['operation'])}\n", style=RED)
            if multi_region:
                message.append(f"Region / scope: {terminal_text(entry.get('region') or entry.get('scope') or 'global')}\n", style=CYAN)
            message.append(terminal_text(issue["message"], multiline=True), style=YELLOW)
            errors.print(message)
    console.print("Scope: configuration risk indicators; effective access is not determined.", style=YELLOW, markup=False)
