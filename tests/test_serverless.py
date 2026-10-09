from datetime import date
from unittest.mock import Mock
import json
import pytest
import boto3
from awsherlock.aws.context import ScanContext
from awsherlock.collectors.lambda_service import collect_lambda
from awsherlock.collectors.secrets import collect_secrets
from awsherlock.models import Resource
from awsherlock.resource_policy import statements
from awsherlock.rules.serverless import LAMBDA_RULES, SECRET_RULES
from awsherlock.runtime_catalog import runtime_fact
from test_s3 import aws_error


def resource(rule, value):
    return Resource(service=rule.service, resource_type="test", account_id="123456789012", region="eu-west-1",
                    resource_id="test", resource_arn=None, data={rule.required_fact: value})


@pytest.mark.parametrize("rule,bad,good", [
    (LAMBDA_RULES[0], [{"auth": "NONE", "arn": "test"}], [{"auth": "AWS_IAM", "arn": "test"}]),
    (LAMBDA_RULES[1], ["arn:aws:iam::aws:policy/AdministratorAccess"], ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]),
    (LAMBDA_RULES[2], {"deprecated": True}, {"deprecated": False}),
    (SECRET_RULES[0], False, True),
    (SECRET_RULES[1], [{"effect": "Allow", "broad_principal": True}], [{"effect": "Allow", "broad_principal": False}]),
    (SECRET_RULES[2], {"state": "Disabled"}, {"state": "Enabled"}),
])
def test_six_rules(rule, bad, good):
    assert len(rule.evaluate(resource(rule, bad))) == 1
    assert rule.evaluate(resource(rule, good)) == []
    r = resource(rule, bad)
    r.data.clear()
    with pytest.raises(ValueError):
        rule.evaluate(r)


def test_policy_context():
    normal = {"Statement": {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*", "Resource": "*"}}
    assert not statements(normal)[0]["broad_principal"]
    normal["Statement"]["Principal"] = "*"
    normal["Statement"]["Condition"] = {"StringEquals": {"secret-marker": "hidden"}}
    normalized = statements(json.dumps(normal))
    assert normalized[0]["broad_principal"] and normalized[0]["conditional"]
    assert "secret-marker" not in repr(normalized)
    normal["Statement"]["Effect"] = "Deny"
    assert not SECRET_RULES[1].evaluate(resource(SECRET_RULES[1], statements(normal)))


def test_runtime_dates():
    assert runtime_fact("python3.9", date(2026, 9, 15))["deprecated"]
    assert not runtime_fact("python3.10", date(2026, 10, 30))["deprecated"]
    assert runtime_fact("python3.10", date(2026, 10, 31))["deprecated"]
    with pytest.raises(ValueError):
        runtime_fact("unknown-runtime", date(2026, 9, 15))


@pytest.fixture
def context():
    session = Mock()
    clients = {name: Mock() for name in ("lambda", "iam", "secretsmanager", "kms")}
    session.client.side_effect = lambda name, **kwargs: clients[name]
    function = {"FunctionName": "test", "FunctionArn": "arn:aws:lambda:eu-west-1:123456789012:function:test", "Role": "arn:aws:iam::123456789012:role/path/execute", "Runtime": "python3.12", "PackageType": "Zip", "Environment": {"Variables": {"password": "secret-marker"}}}
    lambda_pages = {"list_functions": [{"Functions": [function]}], "list_function_url_configs": [{"FunctionUrlConfigs": []}, {"FunctionUrlConfigs": [{"FunctionArn": function["FunctionArn"] + ":alias", "AuthType": "NONE"}]}]}
    clients["lambda"].get_paginator.side_effect = lambda method: Mock(paginate=Mock(return_value=lambda_pages[method]))
    clients["iam"].get_paginator.return_value.paginate.return_value = [{"AttachedPolicies": []}]
    clients["secretsmanager"].get_paginator.return_value.paginate.return_value = [{"SecretList": [{"Name": "test-secret", "ARN": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:test-secret", "RotationEnabled": True}]}]
    clients["secretsmanager"].get_resource_policy.return_value = {}
    return ScanContext("123456789012", "arn:aws:iam::123456789012:root", "aws", None, "eu-west-1", session)


def test_collectors_exclude_secrets(context):
    functions = collect_lambda(context, today=date(2026, 9, 15))
    secrets = collect_secrets(context)
    assert not functions.issues and not secrets.issues
    assert len(functions.resources[0].data["urls"]) == 1
    assert secrets.resources[0].data["encryption"] == {"manager": "AWS", "state": "Enabled"}
    assert "secret-marker" not in repr(functions) + repr(secrets)
    client = context.session.client("secretsmanager")
    client.get_secret_value.assert_not_called()
    client.batch_get_secret_value.assert_not_called()
    context.session.client("lambda").get_function.assert_not_called()


@pytest.mark.parametrize("collector,service,method", [(collect_lambda, "lambda", "get_paginator"), (collect_secrets, "secretsmanager", "get_resource_policy")])
def test_denied(context, collector, service, method):
    getattr(context.session.client(service), method).side_effect = aws_error("AccessDenied")
    result = collector(context)
    assert result.issues
    assert result.issues[0].message == "AccessDenied"
    assert "secret-marker" not in repr(result)


def test_url_paginator_exists():
    client = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name="eu-west-1").client("lambda")
    assert client.can_paginate("list_function_url_configs")


def test_secrets_key_state_and_denial(context):
    client = context.session.client("secretsmanager")
    client.get_paginator.return_value.paginate.return_value[0]["SecretList"][0]["KmsKeyId"] = "key-id"
    kms = context.session.client("kms")
    kms.describe_key.return_value = {"KeyMetadata": {"KeyState": "PendingDeletion", "KeyManager": "CUSTOMER"}}
    result = collect_secrets(context)
    assert SECRET_RULES[2].evaluate(result.resources[0])
    kms.describe_key.side_effect = aws_error("AccessDenied")
    result = collect_secrets(context)
    assert "encryption" not in result.resources[0].data
    assert result.issues[0].message == "AccessDenied"
