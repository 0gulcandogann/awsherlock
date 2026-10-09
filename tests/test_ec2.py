from unittest.mock import Mock
import pytest
from awsherlock.aws.context import ScanContext
from awsherlock.collectors.ec2 import collect_ec2, ingress_facts, instance_facts
from awsherlock.models import Resource
from awsherlock.rules.ec2 import EC2_RULES
from test_s3 import aws_error


def resource(data):
    return Resource(service="ec2", resource_type="test", account_id="123456789012", region="eu-west-1",
                    resource_id="test", resource_arn=None, data=data)


@pytest.mark.parametrize("index,port", [(0, 22), (1, 3389), (2, 5432)])
@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0"])
@pytest.mark.parametrize("protocol", ["tcp", "6", "-1"])
def test_exposure(index, port, cidr, protocol):
    value = [{"protocol": protocol, "from": port-1, "to": port+1, "cidrs": [cidr]}]
    assert EC2_RULES[index].evaluate(resource({"ingress": value}))
    value[0]["cidrs"] = ["10.0.0.0/8"]
    assert EC2_RULES[index].evaluate(resource({"ingress": value})) == []


@pytest.mark.parametrize("protocol", ["udp", "17", "icmp", "1", "58"])
def test_non_tcp_does_not_imply_ssh(protocol):
    data = {"ingress": [{"protocol": protocol, "from": 22, "to": 22, "cidrs": ["::/0"]}]}
    assert EC2_RULES[0].evaluate(resource(data)) == []


@pytest.mark.parametrize("index,bad,good", [(3, {"endpoint": "enabled", "tokens": "optional"}, {"endpoint": "disabled", "tokens": "optional"}),
                                          (4, ["203.0.113.1", "2001:db8::1"], []), (5, False, True)])
def test_instance_and_volume_rules(index, bad, good):
    rule = EC2_RULES[index]
    assert rule.evaluate(resource({rule.required_fact: bad}))
    assert not rule.evaluate(resource({rule.required_fact: good}))
    with pytest.raises(ValueError):
        rule.evaluate(resource({}))


def test_malformed_ingress():
    with pytest.raises(ValueError):
        ingress_facts({"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 100, "ToPort": 1}]})
    assert ingress_facts({"IpPermissions": [{"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]})["ingress"][0]["cidrs"] == ["::/0"]


def test_udp_rdp_and_private_ipv6():
    assert EC2_RULES[1].evaluate(resource({"ingress": [{"protocol": "udp", "from": 3389, "to": 3389, "cidrs": ["::/0"]}]}))
    data = instance_facts({"MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "required"},
                          "NetworkInterfaces": [{"Ipv6Addresses": [{"Ipv6Address": "fd00::1"}, {"Ipv6Address": "2001:4860::1"}]}]})
    assert data["addresses"] == ["2001:4860::1"]


@pytest.fixture
def context():
    session = Mock()
    pages = {
        "describe_security_groups": [{"SecurityGroups": [{"GroupId": "sg-test", "IpPermissions": []}]}],
        "describe_instances": [{"Reservations": [{"Instances": [{"InstanceId": "i-test", "MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "required"}, "NetworkInterfaces": []}]}]}],
        "describe_volumes": [{"Volumes": [{"VolumeId": "vol-first", "Encrypted": True}]}, {"Volumes": [{"VolumeId": "vol-second", "Encrypted": False}]}],
    }
    session.client.return_value.get_paginator.side_effect = lambda method: Mock(paginate=Mock(return_value=pages[method]))
    return ScanContext("123456789012", "arn:aws:iam::123456789012:root", "aws", None, "eu-west-1", session)


def test_collection(context):
    result = collect_ec2(context)
    assert not result.issues
    assert len(result.resources) == 4
    assert result.resources[-1].resource_arn == "arn:aws:ec2:eu-west-1:123456789012:volume/vol-second"
    context.session.client.assert_called_once_with("ec2", region_name="eu-west-1")


def test_denied(context):
    context.session.client.return_value.get_paginator.side_effect = aws_error("UnauthorizedOperation")
    result = collect_ec2(context)
    assert len(result.issues) == 3
    assert not result.resources
    assert all(issue.message == "AccessDenied" for issue in result.issues)


def test_missing_region(context):
    from dataclasses import replace
    result = collect_ec2(replace(context, region=None))
    assert result.issues
    context.session.client.assert_not_called()
