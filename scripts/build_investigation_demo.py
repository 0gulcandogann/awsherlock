"""Build the synthetic investigation demo snapshot (offline, invented identifiers)."""

import sys
from datetime import datetime, timezone
from pathlib import Path

from awsherlock.collectors.common import CollectionResult
from awsherlock.models import (
    Relationship,
    RelationshipEvidence,
    RelationshipType,
    Resource,
    ResourceRef,
    ScanMetadata,
)
from awsherlock.snapshot import Snapshot, write_snapshot

ACCOUNT = "000000000000"
REGION = "eu-central-1"


def ref(item):
    return ResourceRef(
        service=item.service,
        resource_type=item.resource_type,
        account_id=item.account_id,
        region=item.region,
        resource_id=item.resource_id,
        resource_arn=item.resource_arn,
    )


def function(name):
    arn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}"
    return Resource(
        service="lambda", resource_type="function", account_id=ACCOUNT, region=REGION,
        resource_id=name, resource_arn=arn,
        data={
            "urls": [{"arn": arn, "auth": "NONE"}],
            "role_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
            "runtime": {"name": "python3.13", "deprecated": False,
                        "catalog_date": "2026-09-15", "evaluated_on": "2026-10-07"},
        },
    )


def instance(name):
    return Resource(
        service="ec2", resource_type="instance", account_id=ACCOUNT, region=REGION,
        resource_id=name, resource_arn=f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{name}",
        data={"metadata": {"endpoint": "enabled", "tokens": "optional"},
              "addresses": ["203.0.113.25"]},
    )


def role(name, principal):
    return Resource(
        service="iam", resource_type="role", account_id=ACCOUNT, region=None,
        resource_id=name, resource_arn=f"arn:aws:iam::{ACCOUNT}:role/{name}",
        data={
            "attached": ["arn:aws:iam::aws:policy/AdministratorAccess"],
            "statements": [],
            "identity_requested": True,
            "identity_profile": {"owner": True, "purpose": True, "declared_kind": "workload",
                                 "boundary": None, "service_linked": False},
            "identity_approval": {"status": "registered", "declared_kind": "workload",
                                  "owner": True, "purpose": True,
                                  "allowed_principals": [principal], "shared": False,
                                  "external_id_required": False,
                                  "source_identity_required": False},
            "identity_policy_context": {"complete": True, "managed_sources": []},
            "identity_usage": {"created_days": 200, "last_used_days": 2, "status": "recorded"},
            "identity_trust": {"principals": [{"kind": "Service", "value": principal}],
                               "mechanisms": ["aws_service"], "broad": False,
                               "status": "supported", "external_id_condition": False,
                               "source_identity_condition": False},
        },
    )


def bucket(name):
    return Resource(
        service="s3", resource_type="bucket", account_id=ACCOUNT, region=REGION,
        resource_id=name, resource_arn=f"arn:aws:s3:::{name}",
        data={"public_access_block": None, "encryption": ["AES256"],
              "versioning": None, "policy_public": False},
    )


def runs_as(workload, target):
    return Relationship(
        source=ref(workload), relationship_type=RelationshipType.RUNS_AS, target=ref(target),
        evidence=(RelationshipEvidence(service="iam", fact="identity_bindings"),),
    )


def build() -> Snapshot:
    fn = function("example-webhook-handler")
    vm = instance("i-00000000000000001")
    fn_role = role("example-webhook-role", "lambda.amazonaws.com")
    vm_role = role("example-batch-role", "ec2.amazonaws.com")
    data = bucket("example-demo-bucket")
    services = {}
    for item in (fn, vm, fn_role, vm_role, data):
        services.setdefault(item.service, CollectionResult()).resources.append(item)
    metadata = ScanMetadata(
        scan_id="synthetic-investigation-demo",
        started_at=datetime(2026, 10, 7, tzinfo=timezone.utc),
        account_id=ACCOUNT, region=REGION, version="0.5.1",
    )
    return Snapshot(metadata, services, [runs_as(fn, fn_role), runs_as(vm, vm_role)], 2)


if __name__ == "__main__":
    write_snapshot(build(), Path(sys.argv[1]))
