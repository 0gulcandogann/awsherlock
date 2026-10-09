"""Bounded service collection remains deterministic and scope-safe."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, Event, Lock, current_thread
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from awsherlock.aws.context import ScanContext
from awsherlock.collectors.common import CollectionIssue, CollectionResult
from awsherlock.measurement import ScanMeasurements
from awsherlock.models import Resource
from awsherlock.snapshot import capture_snapshot
from awsherlock.evaluation import evaluate_snapshot
from awsherlock.html_report import HtmlScope
from awsherlock.leads import investigation_leads
from awsherlock.organization import scan_organization
from awsherlock.regional import scan_regions
from awsherlock.reporting import render_html, render_json
from awsherlock.sarif import render_sarif
from test_s3 import context


SERVICES = ["iam", "s3", "ec2", "lambda"]


def _resource(service: str) -> Resource:
    return Resource(service=service, resource_type="synthetic",
                    account_id="123456789012", region="eu-west-1",
                    resource_id=service, resource_arn=None, data={})


def test_parallel_collectors_overlap_without_exceeding_bound(context, monkeypatch):
    lock = Lock()
    release = Event()
    two_active = Event()
    active = maximum = 0
    calls = Counter()

    def components(service):
        def collect(target):
            nonlocal active, maximum
            with lock:
                calls[service] += 1
                active += 1
                maximum = max(maximum, active)
                if active == 2:
                    two_active.set()
            assert release.wait(2)
            with lock:
                active -= 1
            return CollectionResult()
        return collect, []

    monkeypatch.setattr("awsherlock.snapshot.service_components", components)
    with ThreadPoolExecutor(max_workers=1) as outer:
        future = outer.submit(capture_snapshot, context, SERVICES, max_workers=2)
        assert two_active.wait(2)
        release.set()
        snapshot = future.result(timeout=2)

    assert maximum == 2
    assert calls == Counter({service: 1 for service in SERVICES})
    assert list(snapshot.services) == SERVICES


def test_parallel_reverse_completion_keeps_requested_result_and_progress_order(context, monkeypatch):
    gates = {service: Event() for service in SERVICES}
    started = Barrier(len(SERVICES) + 1)
    events = []

    def components(service):
        def collect(target):
            started.wait(timeout=2)
            assert gates[service].wait(2)
            return CollectionResult([_resource(service)], [CollectionIssue(None, service, "issue")])
        return collect, []

    monkeypatch.setattr("awsherlock.snapshot.service_components", components)
    with ThreadPoolExecutor(max_workers=1) as outer:
        future = outer.submit(capture_snapshot, context, SERVICES,
                              progress=lambda *event: events.append(event), max_workers=4)
        started.wait(timeout=2)
        for service in reversed(SERVICES):
            gates[service].set()
        snapshot = future.result(timeout=2)

    assert list(snapshot.services) == SERVICES
    assert [snapshot.services[name].resources[0].resource_id for name in SERVICES] == SERVICES
    assert events == [event for index, service in enumerate(SERVICES)
                      for event in ((f"Scanning {service.upper()}", index, len(SERVICES)),
                                    (f"Collected {service.upper()}", index + 1, len(SERVICES)))]


def test_serial_collection_uses_calling_thread_and_no_executor(context, monkeypatch):
    threads = []
    monkeypatch.setattr("awsherlock.snapshot.service_components",
                        lambda service: (lambda target: threads.append(current_thread().name) or CollectionResult(), []))
    snapshot = capture_snapshot(context, SERVICES[:2], max_workers=1)
    assert list(snapshot.services) == SERVICES[:2]
    assert threads == [current_thread().name, current_thread().name]


def test_serial_collection_does_not_construct_executor(context, monkeypatch):
    monkeypatch.setattr("awsherlock.snapshot.service_components",
                        lambda service: (lambda target: CollectionResult(), []))
    monkeypatch.setattr("awsherlock.snapshot.ThreadPoolExecutor",
                        Mock(side_effect=AssertionError("executor must not be constructed")))
    capture_snapshot(context, SERVICES[:2], max_workers=1)


def test_four_workers_are_a_hard_upper_bound(context, monkeypatch):
    services = ["iam", "s3", "ec2", "lambda", "kms", "rds"]
    lock = Lock()
    release = Event()
    four_active = Event()
    active = maximum = 0

    def components(service):
        def collect(target):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
                if active == 4:
                    four_active.set()
            assert release.wait(2)
            with lock:
                active -= 1
            return CollectionResult()
        return collect, []

    monkeypatch.setattr("awsherlock.snapshot.service_components", components)
    with ThreadPoolExecutor(max_workers=1) as outer:
        future = outer.submit(capture_snapshot, context, services, max_workers=4)
        assert four_active.wait(2)
        release.set()
        future.result(timeout=2)
    assert maximum == 4


@pytest.mark.parametrize("failure", [RuntimeError("bug"), KeyboardInterrupt()])
def test_unexpected_failure_cancels_queued_work_and_propagates(context, monkeypatch, failure):
    first_started = Event()
    fail_now = Event()
    second_started = Event()
    release_first = Event()
    queued_cancelled = Event()
    calls = []

    class TrackingExecutor(ThreadPoolExecutor):
        def shutdown(self, wait=True, *, cancel_futures=False):
            if cancel_futures:
                super().shutdown(wait=False, cancel_futures=True)
                queued_cancelled.set()
                if wait:
                    for thread in self._threads:
                        thread.join()
                return
            super().shutdown(wait=wait, cancel_futures=cancel_futures)

    def components(service):
        def collect(target):
            calls.append(service)
            if service == "iam":
                first_started.set()
                assert release_first.wait(2)
            if service == "s3":
                second_started.set()
                assert fail_now.wait(2)
                raise failure
            return CollectionResult()
        return collect, []

    monkeypatch.setattr("awsherlock.snapshot.service_components", components)
    monkeypatch.setattr("awsherlock.snapshot.ThreadPoolExecutor", TrackingExecutor)
    with ThreadPoolExecutor(max_workers=1) as outer:
        future = outer.submit(capture_snapshot, context, SERVICES, max_workers=2)
        assert first_started.wait(2) and second_started.wait(2)
        fail_now.set()
        assert queued_cancelled.wait(2)
        release_first.set()
        with pytest.raises(type(failure), match="bug" if isinstance(failure, RuntimeError) else None):
            future.result(timeout=2)
    assert set(calls) == {"iam", "s3"}


def test_handled_issue_does_not_discard_other_service_results(context, monkeypatch):
    def components(service):
        issues = [CollectionIssue(None, "List", "AccessDenied")] if service == "iam" else []
        return lambda target: CollectionResult([], issues), []

    monkeypatch.setattr("awsherlock.snapshot.service_components", components)
    snapshot = capture_snapshot(context, SERVICES[:2], max_workers=2)
    assert list(snapshot.services) == SERVICES[:2]
    assert snapshot.services["iam"].issues[0].message == "AccessDenied"
    assert snapshot.services["s3"].issues == []


def test_serial_and_parallel_snapshots_and_reports_are_equivalent(context, monkeypatch):
    def components(service):
        return lambda target: CollectionResult(
            [], [CollectionIssue(None, f"{service}-operation", "AccessDenied")]), []

    monkeypatch.setattr("awsherlock.snapshot.service_components", components)
    serial = capture_snapshot(context, SERVICES, max_workers=1)
    parallel = capture_snapshot(context, SERVICES, max_workers=4)
    parallel.metadata = serial.metadata
    assert parallel.to_dict() == serial.to_dict()
    assert evaluate_snapshot(parallel).to_dict() == evaluate_snapshot(serial).to_dict()


def test_relationship_lead_and_report_outputs_match_across_worker_counts(context, monkeypatch):
    from test_leads_v2 import role

    execution_role = role()
    runtime_id = "RuntimeName-abcdefghij"
    execution_role.data["identity_bindings"] = [{
        "service": "agentcore", "region": "eu-west-1",
        "resource_arn": (
            f"arn:aws:bedrock-agentcore:eu-west-1:{context.account_id}:runtime/{runtime_id}"
        ),
        "role_arn": execution_role.resource_arn,
        "resource_version": "2",
    }]
    agent_id = "ABCDEFGHIJ"
    agent = Resource(
        service="bedrock", resource_type="agent", account_id=context.account_id,
        region="eu-west-1", resource_id=agent_id,
        resource_arn=f"arn:aws:bedrock:eu-west-1:{context.account_id}:agent/{agent_id}",
        data={
            "agent_version": "DRAFT",
            "guardrail_configuration": {"identifier": "guardrail123", "version": "1"},
            "execution_role_arn": execution_role.resource_arn,
        },
    )
    resources = {"iam": [execution_role], "bedrock": [agent]}
    monkeypatch.setattr(
        "awsherlock.snapshot.service_components",
        lambda service: (lambda target: CollectionResult(resources[service], []), []),
    )
    target = replace(context, region="eu-west-1")
    serial = capture_snapshot(target, ["iam", "bedrock"], max_workers=1)
    parallel = capture_snapshot(target, ["iam", "bedrock"], max_workers=2)
    parallel.metadata = serial.metadata
    serial_report = evaluate_snapshot(serial)
    parallel_report = evaluate_snapshot(parallel)

    assert parallel.to_dict() == serial.to_dict()
    assert parallel_report.to_dict() == serial_report.to_dict()
    parallel_leads = investigation_leads(parallel, report=parallel_report)
    assert parallel_leads == investigation_leads(serial, report=serial_report)
    assert [lead["pattern_id"] for lead in parallel_leads["leads"]].count(
        "AI-WORKLOAD-BROAD-EXECUTION-ROLE") == 2
    assert len(parallel.relationships) == 2
    assert render_json(parallel_report) == render_json(serial_report)
    assert render_sarif(parallel_report) == render_sarif(serial_report)
    assert render_html(parallel_report, scopes=[HtmlScope(parallel, parallel_report)]) == render_html(
        serial_report, scopes=[HtmlScope(serial, serial_report)])


def test_regional_callbacks_remain_ordered_and_exactly_paired(context, monkeypatch):
    callback_thread = current_thread().name
    captured = []
    monkeypatch.setattr("awsherlock.snapshot.service_components",
                        lambda service: (lambda target: CollectionResult(), []))
    report = scan_regions(
        replace(context, region="eu-west-1"), SERVICES,
        ["eu-west-1", "eu-central-1"], max_workers=2,
        evaluated_scope_sink=lambda saved, evaluated: captured.append(
            (saved, evaluated, current_thread().name)),
    )
    assert [saved.metadata.region for saved, _, _ in captured] == [
        "eu-west-1", "eu-west-1", "eu-central-1"]
    assert all(saved.metadata.scan_id == evaluated.metadata["scan_id"]
               and saved.metadata.account_id == evaluated.metadata["account_id"]
               and saved.metadata.region == evaluated.metadata["region"]
               and thread == callback_thread
               for saved, evaluated, thread in captured)
    assert [entry["region"] for entry in report.coverage] == [
        None, None, "eu-west-1", "eu-west-1", "eu-central-1", "eu-central-1"]


def test_organization_accounts_remain_sequential_with_parallel_services(context, monkeypatch):
    from test_organization import account

    account_ids = ["000000000001", "000000000002"]
    context.session.client.return_value.get_paginator.return_value.paginate.return_value = [
        {"Accounts": [account(1), account(2)]}]
    targets = [replace(context, account_id=account_id,
                       caller_arn=f"arn:aws:iam::{account_id}:role/Reader")
               for account_id in account_ids]
    monkeypatch.setattr("awsherlock.organization.create_scan_context", Mock(side_effect=targets))
    calls = []
    lock = Lock()

    def components(service):
        def collect(target):
            with lock:
                calls.append((target.account_id, service))
            return CollectionResult()
        return collect, []

    monkeypatch.setattr("awsherlock.snapshot.service_components", components)
    captured = []
    scan_organization(
        context, ["iam", "s3"], regions=["eu-west-1"], max_workers=2,
        evaluated_scope_sink=lambda saved, evaluated: captured.append((saved, evaluated)),
    )
    assert {account_id for account_id, _ in calls[:2]} == {account_ids[0]}
    assert {account_id for account_id, _ in calls[2:]} == {account_ids[1]}
    assert [saved.metadata.account_id for saved, _ in captured] == account_ids
    assert all(saved.metadata.scan_id == evaluated.metadata["scan_id"]
               for saved, evaluated in captured)


def test_scan_context_constructs_and_publishes_one_client_under_contention():
    session = Mock()
    client = object()
    session.client.return_value = client
    target = ScanContext("123456789012", "arn:aws:iam::123456789012:root",
                         "aws", None, "eu-west-1", session)
    barrier = Barrier(5)

    def get_client():
        barrier.wait(timeout=2)
        return target.client("kms", region_name="eu-west-1")

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(get_client) for _ in range(4)]
        barrier.wait(timeout=2)
        clients = [future.result(timeout=2) for future in futures]

    assert clients == [client] * 4
    session.client.assert_called_once_with("kms", region_name="eu-west-1")


def test_failed_client_construction_is_not_cached():
    session = Mock()
    client = object()
    session.client.side_effect = [RuntimeError("failed"), client]
    target = ScanContext("123456789012", "arn:aws:iam::123456789012:root",
                         "aws", None, "eu-west-1", session)
    with pytest.raises(RuntimeError, match="failed"):
        target.client("kms")
    assert target.client("kms") is client
    assert session.client.call_count == 2


def test_measurement_rows_are_canonical_after_concurrent_updates():
    measurements = ScanMeasurements()
    clients = []
    for service, region in [("s3", "us-west-2"), ("kms", "eu-west-1")]:
        client = Mock()
        client.meta.region_name = region
        client.meta.service_model.service_name = service
        client.meta.events = Mock()
        clients.append(client)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(measurements.instrument, client, "123456789012", "identity")
                   for client in clients]
        for future in futures:
            future.result(timeout=2)
    rows = measurements.to_dict()["clients"]
    assert [(row["region"], row["service"]) for row in rows] == [
        ("eu-west-1", "kms"), ("us-west-2", "s3")]


def test_measurement_event_updates_are_thread_safe():
    measurements = ScanMeasurements()
    client = Mock()
    client.meta.region_name = "eu-west-1"
    client.meta.service_model.service_name = "kms"
    client.meta.events = Mock()
    measurements.instrument(client, "123456789012", "identity")
    handler = client.meta.events.register.call_args.args[1]
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(handler, SimpleNamespace(name="ListKeys"))
                   for _ in range(100)]
        for future in futures:
            future.result(timeout=2)
    assert measurements.to_dict()["calls"] == [{
        "account_id": "123456789012", "identity_scope": 1,
        "region": "eu-west-1", "service": "kms",
        "operation": "ListKeys", "count": 100,
    }]
