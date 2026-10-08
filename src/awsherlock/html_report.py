"""Pure deterministic presentation data for the standalone HTML report."""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import asdict, dataclass
from typing import Iterable
from urllib.parse import urlsplit

from awsherlock.evaluation import Report
from awsherlock.leads import investigation_leads
from awsherlock.models import Resource, ResourceRef
from awsherlock.relationships import relationship_to_dict
from awsherlock.snapshot import Snapshot, SnapshotError


SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
PRIORITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass(frozen=True)
class HtmlScope:
    """One already evaluated snapshot scope; never causes collection/evaluation."""

    snapshot: Snapshot
    report: Report


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _anchor(prefix: str, identity: object) -> str:
    digest = hashlib.sha256(_canonical(identity).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest}"


def _resource_key(value: dict | Resource | ResourceRef) -> tuple[str, str, str, str, str]:
    if isinstance(value, dict):
        return (value["account_id"], value.get("region") or "", value["service"],
                value["resource_type"], value["resource_id"])
    return value.logical_key if isinstance(value, ResourceRef) else (
        value.account_id, value.region or "", value.service, value.resource_type, value.resource_id,
    )


def _finding_key(value: dict) -> tuple[str, str, str, str, str]:
    return (value["id"], value["service"], value["account_id"],
            value.get("region") or "", value["resource_id"])


def _finding_ref_key(value: dict) -> tuple[str, str, str, str, str]:
    return (value["check_id"], value["service"], value["account_id"],
            value.get("region") or "", value["resource_id"])


def _relationship_key(value: dict) -> tuple:
    return (_resource_key(value["source"]), value["type"], _resource_key(value["target"]))


def _safe_https_url(value: str) -> str | None:
    if (not isinstance(value, str) or any(character.isspace() for character in value)
            or "\\" in value or any(ord(character) < 32 for character in value)):
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.netloc or parsed.hostname is None
                or parsed.username is not None or parsed.password is not None):
            return None
        if parsed.port is not None or parsed.netloc.lower() != parsed.hostname:
            return None
        labels = parsed.hostname.split(".")
        if (any(not label or len(label) > 63 or
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label) is None
                for label in labels)):
            return None
    except ValueError:
        return None
    return value


def _ordered_report(report: Report) -> dict:
    data = report.to_dict()
    data["metadata"] = deepcopy(data["metadata"])
    data["findings"] = sorted(data["findings"], key=lambda item: (
        SEVERITY_RANK[item["severity"]], item["account_id"], item.get("region") or "",
        item["service"], item["id"], item["resource_id"], item.get("resource_arn") or "",
    ))
    for finding in data["findings"]:
        finding["anchor"] = _anchor(
            "finding", [_finding_key(finding), finding.get("resource_arn") or ""],
        )
        finding["resource"] = {"href": None, "ambiguous": False}
        finding["references"] = [
            {"text": reference, "href": _safe_https_url(reference)}
            for reference in finding["references"]
        ]
    ordered_coverage = []
    for entry in data["coverage"]:
        item = dict(entry)
        item["issues"] = sorted((dict(issue) for issue in entry["issues"]), key=lambda issue: (
            issue["operation"], issue.get("resource_id") or "", issue["message"],
        ))
        item["anchor"] = _anchor("coverage", [
            item["account_id"], item.get("region") or "", item.get("scope") or "",
            item["service"],
        ])
        ordered_coverage.append(item)
    data["coverage"] = sorted(ordered_coverage, key=lambda item: (
        item["account_id"], item.get("region") or "", item.get("scope") or "",
        item["service"], item["status"],
    ))
    if "identities" in data:
        data["identities"] = sorted(data["identities"], key=lambda item: (
            item["account_id"], item["type"], item["name"], item.get("arn") or "",
        ))
    if "suppressions" in data:
        data["suppressions"] = sorted(data["suppressions"], key=lambda item: (
            item["account_id"], item["check_id"], item["resource_id"], item["expires_on"],
        ))
    if "accounts" in data["metadata"]:
        data["metadata"]["accounts"] = sorted(
            data["metadata"]["accounts"], key=lambda item: item["account_id"],
        )
    return data


def _scope_key(scope: HtmlScope) -> tuple[str, str, str]:
    metadata = scope.snapshot.metadata
    return (metadata.account_id, metadata.region or "", metadata.scan_id)


def build_html_view(report: Report, scopes: Iterable[HtmlScope] = ()) -> dict:
    """Build a detached, canonical and safe view without evaluating or collecting."""
    scope_values = tuple(sorted(scopes, key=_scope_key))
    report_data = _ordered_report(report)
    if not scope_values:
        return {
            "available": False,
            "relationship_capability": "unavailable",
            "scopes": [], "leads": [], "relationships": [], "resources": [],
            "priority": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "coverage_status": _coverage_counts(report_data["coverage"]),
            "report": report_data,
        }

    resource_values: dict[tuple, list[Resource]] = {}
    relationship_values: dict[tuple, dict] = {}
    lead_values: dict[str, dict] = {}
    scope_views = []
    capabilities = set()
    for scope in scope_values:
        snapshot = scope.snapshot
        report_scan_id = scope.report.metadata.get("scan_id")
        if (not isinstance(report_scan_id, str)
                or report_scan_id != snapshot.metadata.scan_id
                or scope.report.metadata.get("account_id") != snapshot.metadata.account_id
                or scope.report.metadata.get("region") != snapshot.metadata.region):
            raise SnapshotError("HTML scope report does not match its snapshot scope")
        capabilities.add(snapshot.supports_relationships)
        scope_views.append({
            "account_id": snapshot.metadata.account_id,
            "region": snapshot.metadata.region,
            "scan_id": snapshot.metadata.scan_id,
            "schema_version": snapshot.schema_version,
            "supports_relationships": snapshot.supports_relationships,
        })
        for collection in snapshot.services.values():
            for resource in collection.resources:
                resource_values.setdefault(_resource_key(resource), []).append(resource)
        for relationship in snapshot.relationships:
            raw = relationship_to_dict(relationship)
            key = _relationship_key(raw)
            current = relationship_values.get(key)
            if current is None:
                relationship_values[key] = raw
            else:
                for endpoint in ("source", "target"):
                    current_arn = current[endpoint].get("resource_arn")
                    observed_arn = raw[endpoint].get("resource_arn")
                    if current_arn and observed_arn and current_arn != observed_arn:
                        raise SnapshotError("Conflicting relationship locators in HTML scopes")
                    if current_arn is None and observed_arn is not None:
                        current[endpoint]["resource_arn"] = observed_arn
                evidence = {_canonical(item): item for item in current["evidence"] + raw["evidence"]}
                current["evidence"] = [evidence[item] for item in sorted(evidence)]
        for lead in investigation_leads(snapshot, report=scope.report)["leads"]:
            current = lead_values.get(lead["lead_id"])
            if current is None:
                lead_values[lead["lead_id"]] = lead
            elif current != lead:
                raise SnapshotError("Conflicting HTML lead support for one logical lead")

    resource_entries = []
    resource_links: dict[tuple, list[dict]] = {}
    for key, values in sorted(resource_values.items()):
        unique = {(value.resource_arn or "", value.resource_type): value for value in values}
        for _locator, resource in sorted(unique.items()):
            item = _resource_view(asdict(resource), "collected")
            resource_entries.append(item)
            resource_links.setdefault(key, []).append(item)

    for raw in relationship_values.values():
        for endpoint in (raw["source"], raw["target"]):
            key = _resource_key(endpoint)
            all_matches = resource_links.get(key, [])
            matches = all_matches
            if endpoint.get("resource_arn") is not None:
                matches = [item for item in matches
                           if item.get("resource_arn") == endpoint["resource_arn"]]
                if not matches and all_matches:
                    observed = {item.get("resource_arn") for item in all_matches
                                if item.get("resource_arn") is not None}
                    if observed:
                        raise SnapshotError("Relationship locator conflicts with an HTML resource")
                    item = all_matches[0]
                    item["resource_arn"] = endpoint["resource_arn"]
                    item["anchor"] = _anchor(
                        "resource", [_resource_key(item), item["resource_arn"]],
                    )
                    matches = [item]
            if not matches:
                item = _resource_view(endpoint, "relationship-only")
                resource_entries.append(item)
                resource_links.setdefault(key, []).append(item)

    relationships = []
    relationship_links: dict[tuple, list[dict]] = {}
    for key, raw in sorted(relationship_values.items(), key=lambda item: _canonical(item[1])):
        logical_key = _relationship_key(raw)
        item = {
            **raw,
            "anchor": _anchor("relationship", logical_key),
            "source": _reference_view(raw["source"], resource_links),
            "target": _reference_view(raw["target"], resource_links),
            "evidence": sorted(raw["evidence"], key=lambda evidence: (
                evidence["service"], evidence["fact"], evidence.get("operation") or "",
            )),
        }
        relationships.append(item)
        relationship_links.setdefault(logical_key, []).append(item)
        for endpoint in (item["source"], item["target"]):
            if endpoint.get("href"):
                anchor = endpoint["href"][1:]
                for resource in resource_entries:
                    if resource["anchor"] == anchor:
                        resource["relationship_hrefs"].append(f"#{item['anchor']}")

    finding_links: dict[tuple, list[dict]] = {}
    for finding in report_data["findings"]:
        finding_links.setdefault(_finding_key(finding), []).append(finding)
        finding["resource"] = _finding_resource_link(finding, resource_links)
        if finding["resource"]["href"]:
            anchor = finding["resource"]["href"][1:]
            for resource in resource_entries:
                if resource["anchor"] == anchor:
                    resource["finding_hrefs"].append(f"#{finding['anchor']}")

    leads = []
    for lead in sorted(lead_values.values(), key=lambda item: (
        PRIORITY_RANK[item["priority"]], item["pattern_id"], item["lead_id"],
    )):
        item = dict(lead)
        item["anchor"] = _anchor("lead", lead["lead_id"])
        item["subjects"] = [_reference_view(ref, resource_links, relationship_only=True)
                            for ref in lead["subjects"]]
        item["related_resources"] = [_reference_view(ref, resource_links)
                                     for ref in lead["related_resources"]]
        item["findings"] = [_lead_finding_view(ref, finding_links) for ref in lead["findings"]]
        item["relationships"] = [
            _lead_relationship_view(ref, relationship_links) for ref in lead["relationships"]
        ]
        leads.append(item)

    relationship_capability = ("mixed" if len(capabilities) > 1 else
                               "supported" if True in capabilities else "unsupported")
    return {
        "available": True,
        "relationship_capability": relationship_capability,
        "scopes": scope_views,
        "leads": leads,
        "relationships": relationships,
        "resources": sorted(resource_entries, key=lambda item: (
            _resource_key(item), item.get("resource_arn") or "", item["reference_kind"],
        )),
        "priority": {priority: sum(item["priority"] == priority for item in leads)
                     for priority in ("HIGH", "MEDIUM", "LOW")},
        "coverage_status": _coverage_counts(report_data["coverage"]),
        "report": report_data,
    }


def _coverage_counts(coverage: list[dict]) -> dict[str, int]:
    return {status: sum(item["status"] == status for item in coverage)
            for status in ("COMPLETE", "PARTIAL", "ERROR", "NOT_SCANNED")}


def _resource_view(value: dict, kind: str) -> dict:
    item = {name: value.get(name) for name in (
        "service", "resource_type", "account_id", "region", "resource_id", "resource_arn",
    )}
    item["reference_kind"] = kind
    item["anchor"] = _anchor("resource", [_resource_key(item), item.get("resource_arn") or ""])
    item["finding_hrefs"] = []
    item["relationship_hrefs"] = []
    _add_agentcore_version_context(item)
    return item


def _reference_view(reference: dict, resources: dict[tuple, list[dict]],
                    *, relationship_only: bool = False) -> dict:
    matches = resources.get(_resource_key(reference), [])
    if reference.get("resource_arn") is not None:
        matches = [item for item in matches if item.get("resource_arn") == reference["resource_arn"]]
    result = dict(reference)
    _add_agentcore_version_context(result)
    if len(matches) == 1:
        result.update(reference_kind=matches[0]["reference_kind"], href=f"#{matches[0]['anchor']}")
    else:
        result.update(reference_kind=("relationship-only" if relationship_only or not matches
                                      else "unresolved"), href=None)
    return result


def _add_agentcore_version_context(value: dict) -> None:
    if (value.get("service"), value.get("resource_type")) == (
        "agentcore", "runtime-version",
    ):
        runtime_id, separator, version = value["resource_id"].rpartition(":")
        if separator and runtime_id and version:
            value["runtime_id"] = runtime_id
            value["runtime_version"] = version


def _finding_resource_link(finding: dict, resources: dict[tuple, list[dict]]) -> dict:
    key = (finding["account_id"], finding.get("region") or "", finding["service"], finding["resource_id"])
    matches = []
    for resource_key, entries in resources.items():
        if (resource_key[0], resource_key[1], resource_key[2], resource_key[4]) == key:
            matches.extend(entries)
    if finding.get("resource_arn") is not None:
        matches = [item for item in matches if item.get("resource_arn") == finding["resource_arn"]]
    return {"href": f"#{matches[0]['anchor']}" if len(matches) == 1 else None,
            "ambiguous": len(matches) > 1}


def _lead_finding_view(reference: dict, findings: dict[tuple, list[dict]]) -> dict:
    matches = findings.get(_finding_ref_key(reference), [])
    if reference.get("resource_arn") is not None:
        matches = [item for item in matches if item.get("resource_arn") == reference["resource_arn"]]
    return {**reference, "href": f"#{matches[0]['anchor']}" if len(matches) == 1 else None,
            "resolved": len(matches) == 1}


def _lead_relationship_view(reference: dict, relationships: dict[tuple, list[dict]]) -> dict:
    matches = relationships.get(_relationship_key(reference), [])
    return {**reference, "href": f"#{matches[0]['anchor']}" if len(matches) == 1 else None,
            "resolved": len(matches) == 1}
