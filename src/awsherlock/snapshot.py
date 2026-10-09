"""Versioned normalized snapshots, excluding sessions and secret-bearing fields."""

import json
import re
from concurrent.futures import FIRST_EXCEPTION, Future, ThreadPoolExecutor, wait
from contextlib import nullcontext
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from uuid import uuid4

from awsherlock import __version__
from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import CollectionIssue, CollectionResult
from awsherlock.models import Relationship, Resource, ScanMetadata
from awsherlock.relationships import (
    normalize_relationships,
    project_relationships,
    relationship_from_dict,
    relationship_to_dict,
)
from awsherlock.registry import RESOURCE_FACTS, service_spec
from awsherlock.scanner import SERVICES, service_components
from awsherlock.fact_validation import validate_resource_facts

CURRENT_SCHEMA_VERSION = 2
SUPPORTED_SCHEMA_VERSIONS = frozenset({1, CURRENT_SCHEMA_VERSION})
FACTS = RESOURCE_FACTS
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
    relationships: tuple[Relationship, ...] = ()
    schema_version: int = 1

    @property
    def supports_relationships(self) -> bool:
        """Whether this schema can represent positive relationship records."""
        return self.schema_version >= 2

    def to_dict(self) -> dict:
        if type(self.schema_version) is not int or self.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            raise SnapshotError("Unsupported snapshot schema version")
        if self.schema_version == 1 and self.relationships:
            raise SnapshotError("Snapshot schema version 1 cannot contain relationships")
        if any(name not in SERVICES for name in self.services):
            raise SnapshotError("Invalid normalized snapshot data")
        metadata = asdict(self.metadata)
        metadata["started_at"] = self.metadata.started_at.isoformat()
        data = {"schema_version": self.schema_version, "metadata": metadata,
                "services": {name: {"resources": [asdict(resource) for resource in result.resources],
                                    "issues": [asdict(issue) for issue in result.issues],
                                    **({"completed_operations": result.completed_operations}
                                       if service_spec(name).completed_operations and result.completed_operations else {})}
                             for name, result in self.services.items()}}
        if self.supports_relationships:
            relationships = normalize_relationships(self.relationships, self.services)
            data["relationships"] = [relationship_to_dict(item) for item in relationships]
        snapshot_from_dict(data)  # Validate mutable nested facts before writing.
        return data


def _collect_service(context: ScanContext, service: str) -> CollectionResult:
    collector, _ = service_components(service)
    timer = (context.measurements.collection(context.account_id, context.caller_arn,
                                             context.region, service)
             if context.measurements is not None else nullcontext())
    with timer:
        result = collector(context)
    return CollectionResult(result.resources, result.issues,
                            getattr(result, "completed_operations", []))


def capture_snapshot(context: ScanContext, services: list[str],
                     progress: Callable[[str, int, int], None] | None = None,
                     *, max_workers: int = 1) -> Snapshot:
    if type(max_workers) is not int or not 1 <= max_workers <= len(SERVICES):
        raise SnapshotError(f"max_workers must be between 1 and {len(SERVICES)}")
    metadata = ScanMetadata(scan_id=str(uuid4()), started_at=datetime.now(timezone.utc),
                            account_id=context.account_id, region=context.region, version=__version__)
    results = {}
    if max_workers == 1 or len(services) <= 1:
        for index, service in enumerate(services):
            if progress is not None:
                progress(f"Scanning {service.upper()}", index, len(services))
            results[service] = _collect_service(context, service)
            if progress is not None:
                progress(f"Collected {service.upper()}", index + 1, len(services))
    else:
        executor = ThreadPoolExecutor(max_workers=min(max_workers, len(services)),
                                      thread_name_prefix="awsherlock-collect")
        stop = Event()
        futures: list[tuple[str, Future[CollectionResult | None]]] = []

        def collect(service: str) -> CollectionResult | None:
            if stop.is_set():
                return None
            try:
                return _collect_service(context, service)
            except BaseException:
                stop.set()
                raise

        failed: Future[CollectionResult | None] | None = None
        try:
            futures = [(service, executor.submit(collect, service)) for service in services]
            done, _ = wait((future for _, future in futures), return_when=FIRST_EXCEPTION)
            if any(not future.cancelled() and future.exception() is not None for future in done):
                stop.set()
                for _, future in futures:
                    future.cancel()
                executor.shutdown(wait=True, cancel_futures=True)
                failed = next(
                    future for _, future in futures
                    if not future.cancelled() and future.exception() is not None
                )
            else:
                for index, (service, future) in enumerate(futures):
                    if progress is not None:
                        progress(f"Scanning {service.upper()}", index, len(services))
                    result = future.result()
                    if result is None:
                        raise RuntimeError("Collection stopped without a collector failure")
                    results[service] = result
                    if progress is not None:
                        progress(f"Collected {service.upper()}", index + 1, len(services))
                executor.shutdown(wait=True)
        except BaseException:
            stop.set()
            for _, future in futures:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
            raise
        if failed is not None:
            failed.result()
    return Snapshot(metadata, results, project_relationships(results), CURRENT_SCHEMA_VERSION)


def snapshot_from_dict(data: object) -> Snapshot:
    try:
        if not isinstance(data, dict) or type(data.get("schema_version")) is not int:
            raise ValueError()
        schema_version = data["schema_version"]
        if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            raise SnapshotError("Unsupported snapshot schema version")
        expected_keys = {"schema_version", "metadata", "services"}
        if schema_version == 2:
            expected_keys.add("relationships")
        if set(data) != expected_keys:
            raise ValueError()
        _no_secrets(data)
        metadata_data = dict(data["metadata"])
        metadata_data["started_at"] = datetime.fromisoformat(metadata_data["started_at"])
        metadata = ScanMetadata(**metadata_data)
        if not isinstance(data["services"], dict) or not data["services"]:
            raise ValueError()
        services = {}
        for service, collection in data["services"].items():
            if service not in SERVICES or not isinstance(collection, dict) or not {"resources", "issues"} <= set(collection):
                raise ValueError()
            if set(collection) - {"resources", "issues"} != ({"completed_operations"} if "completed_operations" in collection else set()):
                raise ValueError()
            registered_operations = service_spec(service).completed_operations
            if "completed_operations" in collection and not registered_operations:
                raise ValueError()
            if not isinstance(collection["resources"], list) or not isinstance(collection["issues"], list):
                raise ValueError()
            result = CollectionResult()
            if "completed_operations" in collection:
                if collection["completed_operations"] != list(registered_operations):
                    raise ValueError()
                result.completed_operations = list(registered_operations)
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
        relationships = ()
        if schema_version == 2:
            if not isinstance(data["relationships"], list):
                raise ValueError()
            relationships = normalize_relationships(
                (relationship_from_dict(raw) for raw in data["relationships"]),
                services,
            )
        return Snapshot(metadata, services, relationships, schema_version)
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
