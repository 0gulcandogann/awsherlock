"""Versioned normalized snapshots, excluding sessions and secret-bearing fields."""

import json
import re
from contextlib import nullcontext
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from awsherlock import __version__
from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import CollectionIssue, CollectionResult
from awsherlock.models import Resource, ScanMetadata
from awsherlock.scanner import SERVICES, service_components
from awsherlock.fact_validation import validate_resource_facts

SCHEMA_VERSION = 1
FACTS = {
    ("s3", "bucket"): {"public_access_block", "account_public_access_block", "encryption", "versioning", "logging", "policy_public"},
    ("iam", "user"): {"attached", "statements", "console_mfa"},
    **{("iam", kind): {"attached", "statements"} for kind in ("role", "group")},
    ("iam", "policy"): {"statements"},
    ("iam", "access_key"): {"key_age", "key_stale"},
    ("ec2", "security-group"): {"ingress"}, ("ec2", "instance"): {"metadata", "addresses"}, ("ec2", "volume"): {"encrypted"},
    ("lambda", "function"): {"urls", "runtime", "role_policies"},
    ("secretsmanager", "secret"): {"rotation", "policy", "encryption"},
    ("cloudtrail", "trail"): {"trail_settings", "trail_status", "management_events", "management_excluded_sources"},
    ("cloudtrail", "regional_summary"): {"usable_trail"},
    ("kms", "key"): {"rotation", "policy"},
}
IDENTITY_COMMON = {"identity_requested", "identity_profile", "identity_approval", "identity_policy_context",
                   "identity_bindings", "identity_activity", "identity_analyzer_findings"}
FACTS[("iam", "role")] |= IDENTITY_COMMON | {"identity_trust", "identity_usage"}
FACTS[("iam", "user")] |= IDENTITY_COMMON
FORBIDDEN = {"session", "credentials", "accesskeyid", "awsaccesskeyid", "secretaccesskey", "awssecretaccesskey",
             "sessiontoken", "awssessiontoken", "secretstring", "secretbinary", "privatekey", "password", "environment", "variables"}


class SnapshotError(ValueError):
    """A safe user-facing snapshot validation failure."""


def _no_secrets(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if "".join(c for c in key.lower() if c.isalnum()) in FORBIDDEN:
                raise SnapshotError("Snapshot contains a forbidden credential or secret field")
            _no_secrets(child)
    elif isinstance(value, list):
        for child in value:
            _no_secrets(child)


@dataclass
class Snapshot:
    metadata: ScanMetadata
    services: dict[str, CollectionResult]

    def to_dict(self) -> dict:
        metadata = asdict(self.metadata)
        metadata["started_at"] = self.metadata.started_at.isoformat()
        data = {"schema_version": SCHEMA_VERSION, "metadata": metadata,
                "services": {name: {"resources": [asdict(resource) for resource in result.resources],
                                    "issues": [asdict(issue) for issue in result.issues]}
                             for name, result in self.services.items()}}
        snapshot_from_dict(data)  # Validate mutable nested facts before writing.
        return data


def capture_snapshot(context: ScanContext, services: list[str],
                     progress: Callable[[str, int, int], None] | None = None) -> Snapshot:
    metadata = ScanMetadata(scan_id=str(uuid4()), started_at=datetime.now(timezone.utc),
                            account_id=context.account_id, region=context.region, version=__version__)
    results = {}
    for index, service in enumerate(services):
        if progress is not None:
            progress(f"Scanning {service.upper()}", index, len(services))
        collector, _ = service_components(service)
        timer = (context.measurements.collection(context.account_id, context.caller_arn,
                                                 context.region, service)
                 if context.measurements is not None else nullcontext())
        with timer:
            result = collector(context)
        results[service] = CollectionResult(result.resources, result.issues)
        if progress is not None:
            progress(f"Collected {service.upper()}", index + 1, len(services))
    return Snapshot(metadata, results)


def snapshot_from_dict(data: object) -> Snapshot:
    try:
        if not isinstance(data, dict) or set(data) != {"schema_version", "metadata", "services"}:
            raise ValueError()
        if type(data["schema_version"]) is not int or data["schema_version"] != SCHEMA_VERSION:
            raise SnapshotError("Unsupported snapshot schema version")
        _no_secrets(data)
        metadata_data = dict(data["metadata"])
        metadata_data["started_at"] = datetime.fromisoformat(metadata_data["started_at"])
        metadata = ScanMetadata(**metadata_data)
        if not isinstance(data["services"], dict) or not data["services"]:
            raise ValueError()
        services = {}
        for service, collection in data["services"].items():
            if service not in SERVICES or not isinstance(collection, dict) or set(collection) != {"resources", "issues"}:
                raise ValueError()
            if not isinstance(collection["resources"], list) or not isinstance(collection["issues"], list):
                raise ValueError()
            result = CollectionResult()
            for raw in collection["resources"]:
                resource = Resource(**raw)
                if resource.service != service or resource.account_id != metadata.account_id:
                    raise ValueError()
                allowed = FACTS.get((service, resource.resource_type))
                if allowed is None or not set(resource.data) <= allowed:
                    raise ValueError()
                validate_resource_facts(resource)
                result.resources.append(resource)
            for raw in collection["issues"]:
                issue = CollectionIssue(**raw)
                if any(not isinstance(value, str) or not value.strip() for value in (issue.operation, issue.message)):
                    raise ValueError()
                if issue.resource_id is not None and not isinstance(issue.resource_id, str):
                    raise ValueError()
                result.issues.append(issue)
            services[service] = result
        return Snapshot(metadata, services)
    except SnapshotError:
        raise
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError):
        raise SnapshotError("Invalid normalized snapshot data") from None


def write_snapshot(snapshot: Snapshot, path: Path) -> None:
    content = json.dumps(snapshot.to_dict(), indent=2, ensure_ascii=False, allow_nan=False)
    # Do not overwrite an existing artifact silently.
    with path.open("x", encoding="utf-8") as output:
        output.write(content + "\n")


def snapshot_saver(path: Path, *, bundle: bool = False) -> Callable[[Snapshot, str], None]:
    """Save new replayable files; create bundles only after identity is verified."""
    created = False
    def save(snapshot: Snapshot, label: str) -> None:
        nonlocal created
        if not bundle:
            write_snapshot(snapshot, path)
            return
        if not re.fullmatch(r"[a-z0-9-]+", label):
            raise SnapshotError("Invalid snapshot scope label")
        if not created:
            path.mkdir()
            created = True
        write_snapshot(snapshot, path / f"{snapshot.metadata.account_id}-{label}.json")
    return save


def _unique_pairs(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError("Duplicate JSON keys are not allowed")
        result[key] = value
    return result


def read_snapshot(path: Path) -> Snapshot:
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    except (ValueError, RecursionError):
        raise SnapshotError("Invalid snapshot JSON") from None
    return snapshot_from_dict(data)
