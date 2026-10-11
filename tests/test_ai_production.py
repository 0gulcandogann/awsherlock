"""Production AI routing is control-plane evidence, never traffic evidence."""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import boto3
import pytest
from botocore.stub import Stubber
from typer.testing import CliRunner

from awsherlock.aws.context import ScanContext
from awsherlock.cli import app
from awsherlock.collectors.common import CollectionIssue, CollectionResult
from awsherlock.collectors.identity_bindings import collect_identity_bindings
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.diff import compare_snapshots
from awsherlock.html_report import HtmlScope, build_html_view
from awsherlock.identity_config import IdentityOptions
from awsherlock.investigation import build_evidence_pack, render_evidence_json, render_evidence_html
from awsherlock.leads import investigation_leads
from awsherlock.models import ScanMetadata
from awsherlock.relationships import project_relationships, relationship_to_dict
from awsherlock.reporting import render_html
from awsherlock.snapshot import Snapshot, snapshot_from_dict, capture_snapshot
from test_leads_v2 import role

ACCOUNT = '123456789012'
REGION = 'eu-west-1'
RUNTIME = 'Worker-abcdefghij'
ARN = f'arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/{RUNTIME}'
ENDPOINT = ARN + '/runtime-endpoint/production'
NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)
ROLES = {v: f'arn:aws:iam::{ACCOUNT}:role/role{v}' for v in ('2', '3', '5')}


def runtime(version='5', **updates):
    return dict(agentRuntimeArn=ARN, agentRuntimeId=RUNTIME, agentRuntimeVersion=version,
                agentRuntimeName='Worker', createdAt=NOW, lastUpdatedAt=NOW,
                roleArn=ROLES.get(version, ROLES['5']), status='READY', lifecycleConfiguration={},
                environmentVariables={'SECRET': 'EnvironmentSecretMarker'},
                description='DescriptionSecretMarker', **updates)


def endpoint(**updates):
    value = dict(name='production', id='Endpoint-abcdefghij', agentRuntimeArn=ARN,
                 agentRuntimeEndpointArn=ENDPOINT, status='READY', createdAt=NOW,
                 lastUpdatedAt=NOW, liveVersion='2', targetVersion='3',
                 description='EndpointDescriptionSecretMarker')
    value.update(updates)
    return value


def setup():
    core = boto3.client('bedrock-agentcore-control', region_name=REGION,
                        aws_access_key_id='synthetic', aws_secret_access_key='synthetic')
    clients = {'bedrock-agentcore-control': core}
    for service, key in [('lambda', 'Functions'), ('ec2', 'Reservations'),
                         ('bedrock-agent', 'agentSummaries')]:
        clients[service] = Mock()
        clients[service].get_paginator.return_value.paginate.return_value = [{key: []}]
    session = Mock()
    session.client.side_effect = lambda service, **kwargs: clients[service]
    context = ScanContext(ACCOUNT, f'arn:aws:iam::{ACCOUNT}:role/Reader', 'aws', None,
                          REGION, session, identity_options=IdentityOptions(ai_services=True, max_pages=100))
    resources = [role('role' + version, broad_check='AWSH-IAM-001' if version == '2' else 'narrow')
                 for version in ('2', '3', '5')]
    return context, core, CollectionResult(resources), clients


def inventory(stub):
    stub.add_response('list_agent_runtimes', {'agentRuntimes': [{
        'agentRuntimeArn': ARN, 'agentRuntimeId': RUNTIME, 'agentRuntimeVersion': '5',
        'agentRuntimeName': 'Worker', 'description': 'SummarySecretMarker',
        'lastUpdatedAt': NOW, 'status': 'READY'}]}, {})
    stub.add_response('get_agent_runtime', runtime(),
                      {'agentRuntimeId': RUNTIME, 'agentRuntimeVersion': '5'})


def routes(stub, detail=None, versions=('2', '3')):
    detail = endpoint() if detail is None else detail
    stub.add_response('list_agent_runtime_endpoints', {'runtimeEndpoints': [endpoint()]},
                      {'agentRuntimeId': RUNTIME})
    stub.add_response('get_agent_runtime_endpoint', detail,
                      {'agentRuntimeId': RUNTIME, 'endpointName': 'production'})
    for version in versions:
        stub.add_response('get_agent_runtime', runtime(version),
                          {'agentRuntimeId': RUNTIME, 'agentRuntimeVersion': version})


def collect(context, result, *, production=True):
    options = replace(context.identity_options, ai_production=production)
    collect_identity_bindings(replace(context, identity_options=options), result)
    services = {'iam': result}
    value = Snapshot(ScanMetadata(scan_id='production', started_at=NOW, account_id=ACCOUNT,
                                  region=REGION, version='test'), services,
                     project_relationships(services), 2)
    return snapshot_from_dict(value.to_dict())


def uses(value):
    return [edge for edge in value.relationships if edge.relationship_type.value == 'USES']


def test_endpoint_routes_older_live_and_target_not_latest_and_exact_roles():
    context, core, result, _ = setup()
    with Stubber(core) as stub:
        inventory(stub)
        routes(stub)
        value = collect(context, result)
        edges = uses(value)
        assert [(e.source.resource_id, e.target.resource_id, e.target.resource_arn,
                 [(p.fact, p.operation) for p in e.evidence]) for e in edges] == [
            (RUNTIME + ':production', RUNTIME + ':2', None, [('live_version', 'GetAgentRuntimeEndpoint')]),
            (RUNTIME + ':production', RUNTIME + ':3', None, [('target_version', 'GetAgentRuntimeEndpoint')])]
        assert all(e.source.resource_arn == ENDPOINT for e in edges)
        roles = {e.source.resource_id: e.target.resource_arn for e in value.relationships
                 if e.relationship_type.value == 'RUNS_AS'}
        assert roles == {RUNTIME + ':' + v: ROLES[v] for v in ('2', '3', '5')}
        leads = investigation_leads(value)['leads']
        ai = [lead for lead in leads if lead['pattern_id'] == 'AI-WORKLOAD-BROAD-EXECUTION-ROLE']
        assert [lead['subjects'][0]['resource_id'] for lead in ai] == [RUNTIME + ':2']
        assert 'SecretMarker' not in json.dumps(value.to_dict())
        assert not result.issues
        stub.assert_no_pending_responses()


def test_equal_live_target_merges_edge_and_keeps_both_provenance_facts():
    context, core, result, _ = setup()
    with Stubber(core) as stub:
        inventory(stub)
        routes(stub, endpoint(targetVersion='2'), versions=('2',))
        value = collect(context, result)
        assert len(uses(value)) == 1
        assert [p.fact for p in uses(value)[0].evidence] == ['live_version', 'target_version']
        assert uses(value)[0].target.resource_id == RUNTIME + ':2'
        stub.assert_no_pending_responses()


@pytest.mark.parametrize('field,invalid', [
    ('agentRuntimeEndpointArn', ENDPOINT.replace(ACCOUNT, '999999999999')),
    ('agentRuntimeEndpointArn', ENDPOINT.replace(REGION, 'us-east-1')),
    ('agentRuntimeEndpointArn', ENDPOINT.replace('arn:aws:', 'arn:aws-cn:')),
    ('agentRuntimeEndpointArn', ENDPOINT.replace('production', 'other')),
    ('agentRuntimeArn', ARN + 'other'), ('name', 'other'), ('id', 'Other-abcdefghij'),
])
def test_endpoint_identity_mismatch_has_issue_and_no_routes(field, invalid):
    context, core, result, _ = setup()
    with Stubber(core) as stub:
        inventory(stub)
        routes(stub, endpoint(**{field: invalid}), versions=())
        value = collect(context, result)
        assert not uses(value)
        assert result.issues and any(i.operation == 'GetAgentRuntimeEndpoint' for i in result.issues)
        assert len(value.relationships) == 1  # existing latest version binding survives
        stub.assert_no_pending_responses()


@pytest.mark.parametrize('versions', [('2', '0'), ('2', 'DRAFT'), ('2', '01'), ('2', None), (None, '3')])
def test_invalid_or_missing_route_version_preserves_independent_valid_fact(versions):
    context, core, result, _ = setup()
    detail = endpoint()
    for field, version in zip(('liveVersion', 'targetVersion'), versions):
        if version is None:
            detail.pop(field)
        else:
            detail[field] = version
    valid = tuple(v for v in versions if v in ('2', '3'))
    with Stubber(core) as stub:
        inventory(stub)
        routes(stub, detail, versions=valid)
        value = collect(context, result)
        assert [e.target.resource_id for e in uses(value)] == [RUNTIME + ':' + v for v in valid]
        assert result.issues
        assert 'Invalid AWS response' in [i.message for i in result.issues]
        stub.assert_no_pending_responses()


@pytest.mark.parametrize('operation', ['list_agent_runtime_endpoints', 'get_agent_runtime_endpoint'])
@pytest.mark.parametrize('code', ['AccessDeniedException', 'ThrottlingException'])
def test_endpoint_api_failure_is_incomplete_not_successful_empty(operation, code):
    context, core, result, _ = setup()
    with Stubber(core) as stub:
        inventory(stub)
        if operation == 'get_agent_runtime_endpoint':
            stub.add_response('list_agent_runtime_endpoints', {'runtimeEndpoints': [endpoint()]},
                              {'agentRuntimeId': RUNTIME})
        params = {'agentRuntimeId': RUNTIME}
        if operation == 'get_agent_runtime_endpoint':
            params['endpointName'] = 'production'
        stub.add_client_error(operation, code, 'SecretErrorMarker', expected_params=params)
        value = collect(context, result)
        assert not uses(value) and len(value.relationships) == 1
        assert evaluate_snapshot(value).incomplete
        assert 'SecretErrorMarker' not in json.dumps(value.to_dict())
        stub.assert_no_pending_responses()


def test_production_flag_off_preserves_existing_bindings_without_endpoint_calls():
    context, core, result, _ = setup()
    with Stubber(core) as stub:
        inventory(stub)
        value = collect(context, result, production=False)
        assert not uses(value) and len(value.relationships) == 1
        assert value.relationships[0].evidence[0].operation is None
        assert not result.issues
        stub.assert_no_pending_responses()


@pytest.mark.parametrize('args', [[], ['--identity-governance'], ['--identity-ai-services'],
                                 ['snapshot.json', '--identity-governance', '--identity-ai-services']])
def test_cli_production_requires_live_governance_and_ai_identity(args):
    response = CliRunner().invoke(app, ['scan', *args, '--identity-ai-production'])
    assert response.exit_code == 2
    assert 'No such option' not in response.output


def test_cli_production_help_and_valid_preview():
    response = CliRunner().invoke(app, ['scan', '--help'], terminal_width=160, env={'COLUMNS': '160'})
    assert '--identity-ai-production' in response.output
    response = CliRunner().invoke(app, ['scan', '--preview', '--services', 'iam', '--region', REGION,
        '--identity-governance', '--identity-ai-services', '--identity-ai-production'])
    assert response.exit_code == 0


def test_production_role_provenance_is_minimized_and_recognized_by_pack():
    context, core, result, _ = setup()
    with Stubber(core) as stub:
        inventory(stub)
        routes(stub)
        value = collect(context, result)
    selected = next(lead for lead in investigation_leads(value)['leads']
                    if lead['pattern_id'] == 'AI-WORKLOAD-BROAD-EXECUTION-ROLE')
    pack = build_evidence_pack(value, selected['lead_id'])
    assert pack['status'] == 'COMPLETE'
    assert any(p['operation'] == 'GetAgentRuntime' for e in pack['relationships'] for p in e['evidence'])
    assert len(pack['relationships']) == 1
    assert ENDPOINT not in render_evidence_json(pack)
    assert 'SecretMarker' not in render_evidence_json(pack) + render_evidence_html(pack)


def test_endpoint_route_provenance_has_an_exact_evidence_pack_allowlist():
    from awsherlock.investigation import _relationship_evidence

    value = production_snapshot()
    gaps = set()
    projected = [_relationship_evidence(relationship_to_dict(edge), gaps)
                 for edge in uses(value)]
    assert gaps == set()
    assert [[item['fact'] for item in edge['evidence']] for edge in projected] == [
        ['live_version'], ['target_version'],
    ]
    assert all(item['operation'] == 'GetAgentRuntimeEndpoint'
               for edge in projected for item in edge['evidence'])


def test_collection_reconstruction_retains_worker_owned_routing(monkeypatch):
    context, core, result, _ = setup()
    with Stubber(core) as stub:
        inventory(stub)
        routes(stub)
        collect(context, result)
    monkeypatch.setattr('awsherlock.snapshot.service_components',
                        lambda name: (lambda target: result if name == 'iam' else CollectionResult(), []))
    serial = capture_snapshot(context, ['iam', 's3', 'ec2', 'lambda'], max_workers=1)
    parallel = capture_snapshot(context, ['iam', 's3', 'ec2', 'lambda'], max_workers=4)
    parallel.metadata = serial.metadata
    assert len(uses(serial)) == 2
    assert serial.to_dict() == parallel.to_dict()
    assert investigation_leads(serial) == investigation_leads(parallel)


def test_denied_latest_role_read_does_not_prevent_observed_endpoint_version_roles():
    context, core, result, _ = setup()
    with Stubber(core) as stub:
        stub.add_response('list_agent_runtimes', {'agentRuntimes': [{
            'agentRuntimeArn': ARN, 'agentRuntimeId': RUNTIME, 'agentRuntimeVersion': '5',
            'agentRuntimeName': 'Worker', 'description': 'SummarySecretMarker',
            'lastUpdatedAt': NOW, 'status': 'READY'}]}, {})
        stub.add_client_error('get_agent_runtime', 'AccessDeniedException',
                              expected_params={'agentRuntimeId': RUNTIME, 'agentRuntimeVersion': '5'})
        routes(stub)
        value = collect(context, result)
        assert len(uses(value)) == 2
        assert {e.source.resource_id for e in value.relationships if e.relationship_type.value == 'RUNS_AS'} == {
            RUNTIME + ':2', RUNTIME + ':3'}
        assert any(i.operation == 'GetAgentRuntime' and i.message == 'AccessDenied' for i in result.issues)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize('failure', ['denial', 'repeated_token'])
def test_partial_endpoint_pagination_preserves_positive_routes(failure):
    context, core, result, _ = setup()
    with Stubber(core) as stub:
        inventory(stub)
        stub.add_response('list_agent_runtime_endpoints', {'runtimeEndpoints': [endpoint()], 'nextToken': 'next'},
                          {'agentRuntimeId': RUNTIME})
        stub.add_response('get_agent_runtime_endpoint', endpoint(),
                          {'agentRuntimeId': RUNTIME, 'endpointName': 'production'})
        if failure == 'denial':
            stub.add_client_error('list_agent_runtime_endpoints', 'AccessDeniedException', 'SecretMarker',
                                  expected_params={'agentRuntimeId': RUNTIME, 'nextToken': 'next'})
        else:
            stub.add_response('list_agent_runtime_endpoints', {'runtimeEndpoints': [], 'nextToken': 'next'},
                              {'agentRuntimeId': RUNTIME, 'nextToken': 'next'})
        for version in ('2', '3'):
            stub.add_response('get_agent_runtime', runtime(version),
                              {'agentRuntimeId': RUNTIME, 'agentRuntimeVersion': version})
        value = collect(context, result)
        assert len(uses(value)) == 2
        assert result.issues and evaluate_snapshot(value).incomplete
        assert 'SecretMarker' not in json.dumps(value.to_dict())
        stub.assert_no_pending_responses()


@pytest.mark.parametrize('duplicate', [endpoint(), endpoint(targetVersion='4'), endpoint(id='Other-abcdefghij')])
def test_duplicate_endpoint_identity_is_normalized_or_conflict_withdrawn(duplicate):
    context, core, result, _ = setup()
    conflict = duplicate != endpoint()
    with Stubber(core) as stub:
        inventory(stub)
        stub.add_response('list_agent_runtime_endpoints', {'runtimeEndpoints': [endpoint(), duplicate]},
                          {'agentRuntimeId': RUNTIME})
        stub.add_response('get_agent_runtime_endpoint', endpoint(),
                          {'agentRuntimeId': RUNTIME, 'endpointName': 'production'})
        if not conflict:
            for version in ('2', '3'):
                stub.add_response('get_agent_runtime', runtime(version),
                                  {'agentRuntimeId': RUNTIME, 'agentRuntimeVersion': version})
        value = collect(context, result)
        assert len(uses(value)) == (0 if conflict else 2)
        assert bool(result.issues) == conflict
        stub.assert_no_pending_responses()


def test_production_endpoint_issue_order_is_canonical_across_inventory_permutations():
    legacy = [
        CollectionIssue('z-resource', 'LegacyZ', 'legacy z'),
        CollectionIssue('a-resource', 'LegacyA', 'legacy a'),
    ]

    def run(reverse):
        context, core, result, _ = setup()
        result.issues.extend(legacy)
        alpha = endpoint(name='alpha', id='Alpha-abcdefghij',
                         agentRuntimeEndpointArn=ARN + '/runtime-endpoint/alpha')
        beta = endpoint(name='beta', id='Beta-abcdefghij',
                        agentRuntimeEndpointArn=ENDPOINT.replace(ACCOUNT, '999999999999'))
        gamma = endpoint(name='gamma', id='Gamma-abcdefghij',
                         agentRuntimeEndpointArn=ENDPOINT.replace(REGION, 'us-east-1'))
        summaries = [endpoint(), alpha, beta, gamma]
        if reverse:
            summaries.reverse()
        with Stubber(core) as stub:
            inventory(stub)
            stub.add_response('list_agent_runtime_endpoints', {'runtimeEndpoints': summaries},
                              {'agentRuntimeId': RUNTIME})
            for summary in summaries:
                if summary['name'] == 'production':
                    stub.add_response('get_agent_runtime_endpoint', endpoint(),
                                      {'agentRuntimeId': RUNTIME, 'endpointName': 'production'})
                elif summary['name'] == 'alpha':
                    detail = deepcopy(alpha)
                    detail['id'] = 'Wrong-abcdefghij'
                    stub.add_response('get_agent_runtime_endpoint', detail,
                                      {'agentRuntimeId': RUNTIME, 'endpointName': 'alpha'})
            for version in ('2', '3'):
                stub.add_response('get_agent_runtime', runtime(version),
                                  {'agentRuntimeId': RUNTIME, 'agentRuntimeVersion': version})
            value = collect(context, result)
            stub.assert_no_pending_responses()
        return value, result

    first, first_result = run(False)
    reversed_value, reversed_result = run(True)
    expected_new_issues = [
        CollectionIssue(None, 'GetAgentRuntimeEndpoint', 'Invalid AWS response'),
        CollectionIssue(None, 'ListAgentRuntimeEndpoints', 'Invalid AWS response'),
        CollectionIssue(None, 'ListAgentRuntimeEndpoints', 'Invalid AWS response'),
    ]
    assert first_result.issues[:2] == reversed_result.issues[:2] == legacy
    assert first_result.issues[2:] == reversed_result.issues[2:] == expected_new_issues
    assert first.to_dict()['services']['iam']['issues'] == reversed_value.to_dict()['services']['iam']['issues']
    assert first.relationships == reversed_value.relationships
    assert len(uses(first)) == 2
    assert [item.fact for edge in uses(first) for item in edge.evidence] == [
        'live_version', 'target_version',
    ]
    assert json.dumps(first.to_dict(), sort_keys=True, separators=(',', ':')) == json.dumps(
        reversed_value.to_dict(), sort_keys=True, separators=(',', ':'))


def test_nonproduction_identity_collection_preserves_existing_issue_order():
    context, core, result, _ = setup()
    legacy = [
        CollectionIssue('z-resource', 'LegacyZ', 'legacy z'),
        CollectionIssue('a-resource', 'LegacyA', 'legacy a'),
    ]
    result.issues.extend(legacy)
    with Stubber(core) as stub:
        inventory(stub)
        collect(context, result, production=False)
        stub.assert_no_pending_responses()
    assert result.issues == legacy


@pytest.mark.parametrize('field,bad', [
    ('roleArn', ROLES['2'].replace(ACCOUNT, '999999999999')),
    ('roleArn', ROLES['2'].replace('arn:aws:', 'arn:aws-cn:')),
    ('roleArn', ROLES['2'].replace(':role/', ':group/')),
    ('roleArn', ROLES['2'].replace(':role/', ':role/wrong-path/')),
    ('agentRuntimeVersion', '4'), ('agentRuntimeId', 'Other-abcdefghij'),
    ('agentRuntimeArn', ARN.replace(REGION, 'us-east-1')),
])
def test_wrong_version_role_detail_never_creates_broad_version_lead(field, bad):
    context, core, result, _ = setup()
    detail = runtime('2')
    detail[field] = bad
    with Stubber(core) as stub:
        inventory(stub)
        stub.add_response('list_agent_runtime_endpoints', {'runtimeEndpoints': [endpoint(targetVersion='2')]},
                          {'agentRuntimeId': RUNTIME})
        stub.add_response('get_agent_runtime_endpoint', endpoint(targetVersion='2'),
                          {'agentRuntimeId': RUNTIME, 'endpointName': 'production'})
        stub.add_response('get_agent_runtime', detail,
                          {'agentRuntimeId': RUNTIME, 'agentRuntimeVersion': '2'})
        value = collect(context, result)
        assert len(uses(value)) == 1  # route observed independently; role unavailable
        assert result.issues
        assert not any(lead['pattern_id'] == 'AI-WORKLOAD-BROAD-EXECUTION-ROLE'
                       for lead in investigation_leads(value)['leads'])
        stub.assert_no_pending_responses()


def test_missing_role_field_is_not_exported_or_correlated(monkeypatch):
    context, core, result, _ = setup()
    original = core.get_agent_runtime
    def omit(**params):
        response = original(**params)
        if params['agentRuntimeVersion'] == '2':
            response.pop('roleArn')
        return response
    monkeypatch.setattr(core, 'get_agent_runtime', omit)
    with Stubber(core) as stub:
        inventory(stub)
        routes(stub)
        value = collect(context, result)
        assert len(uses(value)) == 2 and result.issues
        assert not any(lead['pattern_id'] == 'AI-WORKLOAD-BROAD-EXECUTION-ROLE'
                       for lead in investigation_leads(value)['leads'])
        stub.assert_no_pending_responses()


@pytest.mark.parametrize('operation', ['list_agent_runtime_endpoints', 'get_agent_runtime_endpoint'])
def test_unsupported_sdk_operation_is_incomplete(monkeypatch, operation):
    context, core, result, _ = setup()
    monkeypatch.setattr(core, operation, None)
    with Stubber(core) as stub:
        inventory(stub)
        if operation == 'get_agent_runtime_endpoint':
            stub.add_response('list_agent_runtime_endpoints', {'runtimeEndpoints': [endpoint()]},
                              {'agentRuntimeId': RUNTIME})
        value = collect(context, result)
        assert not uses(value) and result.issues
        assert len(value.relationships) == 1
        stub.assert_no_pending_responses()


def test_budget_exhaustion_stops_endpoint_reads_and_retains_existing_binding():
    context, core, result, _ = setup()
    context = replace(context, identity_options=replace(context.identity_options, max_pages=5))
    # Three other inventories plus runtime list/detail exhaust five slots.
    with Stubber(core) as stub:
        inventory(stub)
        value = collect(context, result)
        assert len(value.relationships) == 1 and not uses(value)
        assert any(i.operation == 'ListAgentRuntimeEndpoints' for i in result.issues)
        stub.assert_no_pending_responses()


def test_unexpected_endpoint_programming_failure_propagates(monkeypatch):
    context, core, result, _ = setup()
    monkeypatch.setattr(core, 'list_agent_runtime_endpoints', Mock(side_effect=RuntimeError('programming bug')))
    with Stubber(core) as stub:
        inventory(stub)
        with pytest.raises(RuntimeError, match='programming bug'):
            collect(context, result)
        stub.assert_no_pending_responses()


def production_snapshot():
    context, core, result, _ = setup()
    with Stubber(core) as stub:
        inventory(stub)
        routes(stub)
        value = collect(context, result)
        stub.assert_no_pending_responses()
    return value


def test_new_relationships_roundtrip_v2_without_serialized_collector_fields_and_offline(monkeypatch):
    value = production_snapshot()
    monkeypatch.setattr('boto3.session.Session.client', Mock(side_effect=AssertionError('offline AWS client')))
    document = value.to_dict()
    assert document['schema_version'] == 2
    assert set(document['services']['iam']) == {'resources', 'issues'}
    replay = snapshot_from_dict(document)
    assert replay.to_dict() == document
    assert evaluate_snapshot(replay).to_dict() == evaluate_snapshot(value).to_dict()
    leads = investigation_leads(replay)
    selected = next(l for l in leads['leads'] if l['pattern_id'] == 'AI-WORKLOAD-BROAD-EXECUTION-ROLE')
    pack = build_evidence_pack(replay, selected['lead_id'])
    assert pack['status'] == 'COMPLETE'
    assert render_evidence_json(pack) and render_evidence_html(pack)
    legacy = deepcopy(document)
    legacy['schema_version'] = 1
    legacy.pop('relationships')
    v1 = snapshot_from_dict(legacy)
    assert not v1.supports_relationships
    assert not any(l['pattern_id'] == 'AI-WORKLOAD-BROAD-EXECUTION-ROLE'
                   for l in investigation_leads(v1)['leads'])


def test_route_disappearance_is_not_role_remediation_or_new_lead_id():
    before = production_snapshot()
    after = deepcopy(before)
    after.metadata = replace(after.metadata, scan_id='after')
    after.relationships = tuple(e for e in after.relationships if e.relationship_type.value == 'RUNS_AS')
    prior = investigation_leads(before)['leads']
    later = investigation_leads(after)['leads']
    assert [l['lead_id'] for l in prior] == [l['lead_id'] for l in later]
    comparison = compare_snapshots(before, after, include_leads=True)
    assert all(row['state'] == 'STILL_OBSERVED' for row in comparison['lead_delta']['changes'])
    # Missing a version's binding/relationship is uncertainty, never resolution.
    after.relationships = tuple(e for e in after.relationships if e.source.resource_id != RUNTIME + ':2')
    for resource in after.services['iam'].resources:
        resource.data['identity_bindings'] = [b for b in resource.data['identity_bindings']
                                              if b.get('resource_version') != '2']
    comparison = compare_snapshots(before, after, include_leads=True)
    ai = next(row for row in comparison['lead_delta']['changes']
              if row['pattern_id'] == 'AI-WORKLOAD-BROAD-EXECUTION-ROLE')
    assert ai['state'] == 'UNKNOWN'


def test_html_endpoint_navigation_is_exact_and_scope_pairing_stays_strict():
    from awsherlock.snapshot import SnapshotError
    value = production_snapshot()
    report = evaluate_snapshot(value)
    view = build_html_view(report, scopes=[HtmlScope(value, report)])
    endpoint_view = next(r for r in view['resources']
                         if r['resource_type'] == 'runtime-endpoint')
    assert endpoint_view['resource_id'] == RUNTIME + ':production'
    assert endpoint_view['resource_arn'] == ENDPOINT
    assert endpoint_view['reference_kind'] == 'relationship-only'
    assert len(endpoint_view['relationship_hrefs']) == 2
    for edge in view['relationships']:
        assert edge['source']['href'] and edge['target']['href']
    html = render_html(report, scopes=[HtmlScope(value, report)])
    assert ENDPOINT in html and 'SecretMarker' not in html
    wrong = replace(report, metadata={**report.metadata, 'scan_id': 'wrong'})
    with pytest.raises(SnapshotError, match='does not match'):
        render_html(wrong, scopes=[HtmlScope(value, wrong)])


def test_endpoint_malicious_names_are_rejected_without_html_or_json_leak():
    context, core, result, _ = setup()
    malicious = '<svg onload="alert(1)">'
    summary = endpoint(name=malicious, agentRuntimeEndpointArn=ARN + '/runtime-endpoint/' + malicious)
    with Stubber(core) as stub:
        inventory(stub)
        stub.add_response('list_agent_runtime_endpoints', {'runtimeEndpoints': [summary]}, {'agentRuntimeId': RUNTIME})
        value = collect(context, result)
        assert not uses(value) and result.issues
        rendered = render_html(evaluate_snapshot(value), scopes=[HtmlScope(value, evaluate_snapshot(value))])
        assert malicious not in rendered + json.dumps(value.to_dict())
        stub.assert_no_pending_responses()


def test_time_budget_stops_production_read_before_network(monkeypatch):
    from awsherlock.collectors import identity_bindings
    context, core, result, _ = setup()
    clock = [0.0]
    monkeypatch.setattr(identity_bindings.time, 'monotonic', lambda: clock[0])
    original = core.get_agent_runtime
    def elapsed(**params):
        response = original(**params)
        clock[0] = 61.0
        return response
    monkeypatch.setattr(core, 'get_agent_runtime', elapsed)
    with Stubber(core) as stub:
        inventory(stub)
        value = collect(context, result)
        assert not uses(value) and len(value.relationships) == 1 and result.issues
        stub.assert_no_pending_responses()


def test_production_json_html_and_leads_match_across_hash_seeds():
    script = '''
import hashlib,json,socket
from unittest.mock import Mock
from test_ai_production import production_snapshot
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.leads import investigation_leads,render_leads_json
from awsherlock.html_report import HtmlScope
from awsherlock.reporting import render_html
from awsherlock.investigation import build_evidence_pack,render_evidence_json,render_evidence_html
value=production_snapshot()
socket.create_connection=Mock(side_effect=AssertionError("offline network"))
report=evaluate_snapshot(value)
leads=investigation_leads(value,report=report)
lead=next(l for l in leads['leads'] if l['pattern_id']=='AI-WORKLOAD-BROAD-EXECUTION-ROLE')
pack=build_evidence_pack(value,lead['lead_id'])
outputs=[json.dumps(value.to_dict(),sort_keys=True),render_leads_json(leads),
 render_html(report,scopes=[HtmlScope(value,report)]),render_evidence_json(pack),render_evidence_html(pack)]
print(json.dumps([hashlib.sha256(s.encode()).hexdigest() for s in outputs]))
'''
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(Path('src').resolve()), str(Path('tests').resolve())]),
               PYTHONDONTWRITEBYTECODE='1')
    outputs = []
    for seed in ('1', '777'):
        response = subprocess.run([sys.executable, '-c', script], env={**env, 'PYTHONHASHSEED': seed},
                                  capture_output=True, text=True, check=True)
        outputs.append(response.stdout)
    assert outputs[0] == outputs[1]


def test_ai_production_config_requires_ai_services_and_boolean():
    with pytest.raises(ValueError):
        IdentityOptions(ai_production=True)
    with pytest.raises(ValueError):
        IdentityOptions(ai_services=True, ai_production='yes')
