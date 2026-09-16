"""Console and JSON rendering; reporters never collect or evaluate AWS data."""

import json
from pathlib import Path
from rich.console import Console
from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape
from awsherlock.evaluation import Report
from awsherlock.branding import terminal_banner


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


def render_console(report: Report) -> None:
    console = Console()
    errors = Console(stderr=True)
    console.print(terminal_banner(), markup=False, highlight=False)
    console.print(f"Account: {report.metadata['account_id']}", markup=False)
    for account in report.metadata.get("accounts", []):
        console.print(f"Account {account['account_id']} {account['name']}: {account['state']} / {account['scan_status']}", markup=False)
    for entry in report.coverage:
        service = entry["service"]
        for finding in report.findings:
            if finding.service != service or finding.account_id != entry["account_id"]:
                continue
            console.print(f"{finding.severity} {finding.id} {finding.resource_id}: {finding.title}", markup=False)
            console.print(f"  {finding.description}", markup=False)
            console.print(f"  Remediation: {finding.remediation}", markup=False)
        for issue in entry["issues"]:
            errors.print(f"ERROR {entry['account_id']} {service.upper()} {issue['resource_id'] or 'account'} {issue['operation']}: {issue['message']}", markup=False)
        console.print(f"{service.upper()} check coverage: {entry['status']} (account {entry['account_id']})", markup=False)
        label = "Buckets" if service == "s3" else "Resources"
        console.print(f"{label} evaluated: {entry['resources']}; Findings: {entry['findings']}")
        console.print(f"Checks evaluated: {entry['evaluated']}")
        if entry["not_scanned"]:
            console.print(f"Checks not scanned: {entry['not_scanned']}")
    console.print("Scope: configuration risk indicators; effective access is not determined.")
