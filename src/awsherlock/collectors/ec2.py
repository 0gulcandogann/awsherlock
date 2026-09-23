"""Regional EC2 inventory normalized without user data or instance secrets."""

from ipaddress import ip_address, ip_network

from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import AWS_ERRORS, CollectionIssue, CollectionResult, InvalidResponse, collect_fact, error_message, items, text_field
from awsherlock.models import Resource


def ingress_facts(entry: dict) -> dict:
    permissions = []
    for permission in items(entry, "IpPermissions"):
        if not isinstance(permission, dict):
            raise InvalidResponse()
        protocol = text_field(permission.get("IpProtocol"))
        start, end = permission.get("FromPort"), permission.get("ToPort")
        if protocol in {"tcp", "udp", "6", "17"} and (
            type(start) is not int or type(end) is not int or not 0 <= start <= end <= 65535
        ):
            raise InvalidResponse()
        cidrs = []
        for key, field in (("IpRanges", "CidrIp"), ("Ipv6Ranges", "CidrIpv6")):
            for item in items({key: permission.get(key, [])}, key):
                if not isinstance(item, dict):
                    raise InvalidResponse()
                try:
                    cidrs.append(str(ip_network(text_field(item.get(field)), strict=False)))
                except ValueError:
                    raise InvalidResponse() from None
        permissions.append({"protocol": protocol, "from": start, "to": end, "cidrs": cidrs})
    return {"ingress": permissions}


def instance_metadata_fact(entry: dict) -> dict:
    options = entry.get("MetadataOptions")
    if not isinstance(options, dict) or options.get("HttpEndpoint") not in {"enabled", "disabled"} or options.get("HttpTokens") not in {"optional", "required"}:
        raise InvalidResponse()
    return {"endpoint": options["HttpEndpoint"], "tokens": options["HttpTokens"]}


def instance_addresses_fact(entry: dict) -> list[str]:
    addresses = []
    if entry.get("PublicIpAddress"):
        addresses.append(entry["PublicIpAddress"])
    for interface in items(entry, "NetworkInterfaces"):
        if not isinstance(interface, dict):
            raise InvalidResponse()
        association = interface.get("Association", {})
        if not isinstance(association, dict):
            raise InvalidResponse()
        if association.get("PublicIp"):
            addresses.append(association["PublicIp"])
        for address in items({"v6": interface.get("Ipv6Addresses", [])}, "v6"):
            if not isinstance(address, dict):
                raise InvalidResponse()
            addresses.append(address.get("Ipv6Address"))
    try:
        parsed = [ip_address(text_field(address)) for address in addresses]
        return sorted({str(address) for address in parsed if address.version == 4 or address.is_global})
    except ValueError:
        raise InvalidResponse() from None


def instance_facts(entry: dict) -> dict:
    return {"metadata": instance_metadata_fact(entry), "addresses": instance_addresses_fact(entry)}


def volume_facts(entry: dict) -> dict:
    if type(entry.get("Encrypted")) is not bool:
        raise InvalidResponse()
    return {"encrypted": entry["Encrypted"]}


def collect_ec2(context: ScanContext) -> CollectionResult:
    result = CollectionResult()
    if context.region is None:
        result.issues.append(CollectionIssue(None, "Region", "Configure an AWS region for EC2"))
        return result
    try:
        client = context.client("ec2", region_name=context.region)
    except AWS_ERRORS as error:
        result.issues.append(CollectionIssue(None, "EC2Client", error_message(error)))
        return result
    for method, key, kind, id_key, normalize in (
        ("describe_security_groups", "SecurityGroups", "security-group", "GroupId", ingress_facts),
        ("describe_instances", "Reservations", "instance", "InstanceId", instance_facts),
        ("describe_volumes", "Volumes", "volume", "VolumeId", volume_facts),
    ):
        seen = set()
        try:
            for page in client.get_paginator(method).paginate():
                entries = items(page, key)
                if kind == "instance":
                    entries = [entry for reservation in entries for entry in items(reservation, "Instances")]
                for entry in entries:
                    resource_id = None
                    try:
                        if not isinstance(entry, dict):
                            raise InvalidResponse()
                        resource_id = text_field(entry.get(id_key))
                        if resource_id in seen:
                            continue
                        seen.add(resource_id)
                        if kind == "instance" and entry.get("State", {}).get("Name") == "terminated":
                            continue
                        resource = Resource(
                            service="ec2", resource_type=kind, account_id=context.account_id, region=context.region,
                            resource_id=resource_id,
                            resource_arn=f"arn:{context.partition}:ec2:{context.region}:{context.account_id}:{kind}/{resource_id}",
                        )
                        result.resources.append(resource)
                        if kind == "instance":
                            collect_fact(result, resource, "metadata", "describe_instances.metadata",
                                         lambda: instance_metadata_fact(entry))
                            collect_fact(result, resource, "addresses", "describe_instances.addresses",
                                         lambda: instance_addresses_fact(entry))
                        else:
                            fact = "ingress" if kind == "security-group" else "encrypted"
                            collect_fact(result, resource, fact, method, lambda: normalize(entry)[fact])
                    except AWS_ERRORS as error:
                        result.issues.append(CollectionIssue(resource_id, method, error_message(error)))
        except AWS_ERRORS as error:
            result.issues.append(CollectionIssue(None, method, error_message(error)))
    return result
