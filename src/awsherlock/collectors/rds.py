"""Read account-owned RDS snapshot sharing and DB instance encryption facts."""

from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import (AWS_ERRORS, CollectionIssue, CollectionResult,
                                          InvalidResponse, collect_fact, error_message,
                                          items, text_field)
from awsherlock.models import Resource


SNAPSHOT_KINDS = (
    ("db-snapshot", "describe_db_snapshots", "DBSnapshots", "DBSnapshotIdentifier",
     "DBSnapshotArn", "describe_db_snapshot_attributes", "DBSnapshotAttributesResult",
     "DBSnapshotAttributes", "DBSnapshotIdentifier", "DescribeDBSnapshots",
     "DescribeDBSnapshotAttributes"),
    ("db-cluster-snapshot", "describe_db_cluster_snapshots", "DBClusterSnapshots",
     "DBClusterSnapshotIdentifier", "DBClusterSnapshotArn",
     "describe_db_cluster_snapshot_attributes", "DBClusterSnapshotAttributesResult",
     "DBClusterSnapshotAttributes", "DBClusterSnapshotIdentifier",
     "DescribeDBClusterSnapshots", "DescribeDBClusterSnapshotAttributes"),
)


def _restore_public(response: object, result_key: str, attributes_key: str) -> bool:
    if not isinstance(response, dict) or not isinstance(response.get(result_key), dict):
        raise InvalidResponse()
    attributes = items(response[result_key], attributes_key)
    restore = [entry for entry in attributes
               if isinstance(entry, dict) and entry.get("AttributeName") == "restore"]
    if len(restore) != 1 or not isinstance(restore[0].get("AttributeValues"), list):
        raise InvalidResponse()
    values = restore[0]["AttributeValues"]
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise InvalidResponse()
    return "all" in values


def _rds_instance_engine(engine: str) -> bool:
    return (engine in {"mysql", "mariadb", "postgres"}
            or engine.startswith(("db2-", "oracle-", "sqlserver-",
                                  "custom-oracle-", "custom-sqlserver-")))


def _collect_db_instances(client: object, context: ScanContext, result: CollectionResult) -> None:
    seen: set[str] = set()
    try:
        pages = client.get_paginator("describe_db_instances").paginate()
        for page in pages:
            for instance in items(page, "DBInstances"):
                resource_id: str | None = None
                try:
                    if not isinstance(instance, dict):
                        raise InvalidResponse()
                    name = text_field(instance.get("DBInstanceIdentifier"))
                    resource_id = f"db-instance:{name}"
                    arn = text_field(instance.get("DBInstanceArn"))
                    arn_parts = arn.split(":", 6)
                    if (len(arn_parts) != 7 or arn_parts[:3] != ["arn", context.partition, "rds"]
                            or arn_parts[3:6] != [context.region, context.account_id, "db"]
                            or arn_parts[6] != name or name in seen):
                        raise InvalidResponse()
                    seen.add(name)
                    cluster = instance.get("DBClusterIdentifier")
                    if cluster is not None:
                        text_field(cluster)
                        continue  # Cluster-level storage encryption is outside this check.
                    engine = text_field(instance.get("Engine"))
                    if engine.startswith(("aurora", "docdb", "neptune")):
                        continue
                    if not _rds_instance_engine(engine):
                        raise InvalidResponse()
                    resource = Resource(service="rds", resource_type="db-instance",
                                        account_id=context.account_id, region=context.region,
                                        resource_id=resource_id, resource_arn=arn)
                    result.resources.append(resource)

                    def read_encryption() -> bool:
                        value = instance.get("StorageEncrypted")
                        if type(value) is not bool:
                            raise InvalidResponse()
                        return value

                    collect_fact(result, resource, "storage_encrypted", "DescribeDBInstances",
                                 read_encryption)

                    def read_public_access() -> bool:
                        value = instance.get("PubliclyAccessible")
                        if type(value) is not bool:
                            raise InvalidResponse()
                        return value

                    collect_fact(result, resource, "publicly_accessible", "DescribeDBInstances",
                                 read_public_access)
                except AWS_ERRORS as error:
                    result.issues.append(CollectionIssue(resource_id, "DescribeDBInstances",
                                                         error_message(error)))
        result.completed_operations.append("DescribeDBInstances")
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(None, "DescribeDBInstances", error_message(error)))


def collect_rds(context: ScanContext) -> CollectionResult:
    result = CollectionResult()
    if context.region is None:
        result.issues.append(CollectionIssue(None, "Region", "Configure an AWS region for RDS"))
        return result
    try:
        client = context.client("rds", region_name=context.region)
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(None, "RDSClient", error_message(error)))
        return result
    for (kind, list_method, list_key, id_key, arn_key, attributes_method,
         result_key, attributes_key, request_key, list_operation,
         attributes_operation) in SNAPSHOT_KINDS:
        try:
            pages = client.get_paginator(list_method).paginate(SnapshotType="manual")
            for page in pages:
                for snapshot in items(page, list_key):
                    try:
                        if not isinstance(snapshot, dict):
                            raise InvalidResponse()
                        name = text_field(snapshot.get(id_key))
                        arn = text_field(snapshot.get(arn_key))
                        arn_parts = arn.split(":", 6)
                        if (len(arn_parts) != 7 or arn_parts[0] != "arn"
                                or arn_parts[1] != context.partition
                                or arn_parts[2] != "rds"
                                or arn_parts[3] != context.region or arn_parts[4] != context.account_id
                                or arn_parts[5] != ("snapshot" if kind == "db-snapshot" else "cluster-snapshot")
                                or arn_parts[6] != name):
                            raise InvalidResponse()
                        resource = Resource(service="rds", resource_type=kind,
                                            account_id=context.account_id, region=context.region,
                                            resource_id=f"{kind}:{name}", resource_arn=arn)
                        result.resources.append(resource)
                        def read_attributes():
                            response = getattr(client, attributes_method)(**{request_key: name})
                            return _restore_public(response, result_key, attributes_key)
                        collect_fact(result, resource, "restore_public", attributes_operation,
                                     read_attributes)
                    except AWS_ERRORS as error:
                        result.issues.append(CollectionIssue(None, list_operation,
                                                             error_message(error)))
        except AWS_ERRORS as error:
            result.issues.append(CollectionIssue(None, list_operation, error_message(error)))
    _collect_db_instances(client, context, result)
    return result
