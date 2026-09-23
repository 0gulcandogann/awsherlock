"""SARIF 2.1.0 projection of normalized scan results; no AWS or raw evidence."""

import json

from awsherlock import __version__
from awsherlock.catalog import check_catalog
from awsherlock.evaluation import Report
from awsherlock.models import Severity

SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
         Severity.LOW: "note", Severity.INFO: "note"}


def render_sarif(report: Report) -> str:
    """Keep incomplete coverage alongside findings; AWS resources are not files."""
    rules = [{"id": identifier, "name": title, "shortDescription": {"text": title}}
             for identifier, _, title in check_catalog()]
    results = []
    for finding in report.findings:
        resource = finding.resource_arn or finding.resource_id
        qualified = f"{finding.account_id}/{finding.region or 'global'}/{resource}"
        results.append({"ruleId": finding.id, "level": LEVEL[finding.severity],
                        "message": {"text": f"{finding.title}. {finding.description}"},
                        "locations": [{"logicalLocations": [{"name": finding.resource_id,
                                                                "fullyQualifiedName": qualified,
                                                                "kind": "resource"}]}],
                        "properties": {"awsherlockSeverity": finding.severity.value,
                                       "accountId": finding.account_id, "service": finding.service,
                                       "region": finding.region}})
    document = {"$schema": SCHEMA_URI, "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "AWSherlock", "version": __version__,
                                             "informationUri": "https://github.com/0gulcandogann/awsherlock",
                                             "rules": rules}},
                          "results": results,
                          "properties": {"coverage": report.coverage, "incomplete": report.incomplete,
                                         "scope": "Configuration risk indicators; effective access is not determined."}}]}
    return json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
