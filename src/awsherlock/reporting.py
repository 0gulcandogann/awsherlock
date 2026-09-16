"""Console and JSON rendering; reporters never collect or evaluate AWS data."""

import json
from pathlib import Path
from rich.console import Console
from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape
from awsherlock.evaluation import Report
from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


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


SEVERITY_STYLES = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}


def render_console(report: Report) -> None:
    console = Console()
    errors = Console(stderr=True)
    data = report.to_dict()
    summary = data["summary"]
    console.print()
    console.print("AWSherlock / Scan results", style="bold cyan", markup=False)
    console.print(f"Account: {report.metadata['account_id']}", markup=False)
    console.print(f"Region: {report.metadata.get('region') or 'Global / not configured'}", style="dim", markup=False)
    console.print()
    console.print(
        f"{summary['findings']} findings   /   {summary['resources']} resources   /   "
        f"{summary['checks_evaluated']} checks evaluated", style="bold", markup=False,
    )
    severity_line = Text()
    for severity, count in summary["severity"].items():
        severity_line.append(f"{severity} {count}   ", style=SEVERITY_STYLES[severity])
    console.print(severity_line)
    if report.incomplete:
        console.print(Panel("Some checks could not run. Review coverage and collection issues below. "
                            "Zero findings do not mean the account is secure.",
                            title="Incomplete scan coverage", border_style="yellow"))
    accounts = report.metadata.get("accounts", [])
    if accounts:
        table = Table(title="Organization accounts", box=box.SIMPLE, expand=True)
        for label in ("Account", "Name", "State", "Scan status"):
            table.add_column(label)
        for account in accounts:
            table.add_row(*(Text(str(account[key])) for key in ("account_id", "name", "state", "scan_status")))
        console.print(table)
    coverage = Table(title="Scan coverage", box=box.SIMPLE, expand=True)
    for label in ("Account / Service", "Status", "Resources", "Checks", "Not scanned", "Findings"):
        coverage.add_column(label, justify="right" if label in {"Resources", "Checks", "Not scanned", "Findings"} else "left")
    for entry in report.coverage:
        status_style = "green" if entry["status"] == "COMPLETE" else "yellow"
        coverage.add_row(Text(f"{entry['account_id']} / {entry['service'].upper()}"),
                         Text(entry["status"], style=status_style),
                         *(str(entry[key]) for key in ("resources", "evaluated", "not_scanned", "findings")))
    console.print(coverage)
    console.print("Findings", style="bold")
    rank = {severity: index for index, severity in enumerate(SEVERITY_STYLES)}
    findings = sorted(report.findings, key=lambda finding: rank[finding.severity])
    for index, finding in enumerate(findings, 1):
        title = Text(f"{index:02d}  {finding.severity}", style=SEVERITY_STYLES[finding.severity])
        body = Text(f"{finding.title}\n", style="bold")
        body.append(f"{finding.id} / {finding.service.upper()} / {finding.account_id}\n", style="dim")
        body.append(f"Resource: {finding.resource_id}\n")
        body.append(f"{finding.description}\n\n")
        body.append("Remediation: ", style="bold")
        body.append(finding.remediation)
        console.print(Panel(body, title=title, title_align="left", border_style="dim", padding=(1, 2)))
    if not findings:
        console.print("No findings were produced by the evaluated checks. Review scan coverage.", markup=False)
    issues = [(entry, issue) for entry in report.coverage for issue in entry["issues"]]
    if issues:
        errors.print("Collection issues", style="bold yellow")
        for entry, issue in issues:
            message = Text(f"ERROR {entry['account_id']} {entry['service'].upper()} / "
                           f"{issue['resource_id'] or 'account'} / {issue['operation']}\n", style="yellow")
            message.append(issue["message"], style="default")
            errors.print(message)
    console.print("Scope: configuration risk indicators; effective access is not determined.", style="dim", markup=False)
