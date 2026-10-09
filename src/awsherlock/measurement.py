"""Opt-in scan-local SDK invocation counts; never inspect API payloads."""

from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from threading import RLock
from time import perf_counter
from weakref import WeakKeyDictionary

from botocore.client import BaseClient
from botocore.model import OperationModel


@dataclass(frozen=True)
class MeasurementScope:
    account_id: str
    identity: str
    region: str | None


class ScanMeasurements:
    """Use as a context manager; closing removes handlers from all live clients.

    Counts SDK invocations, including Stubber responses and failures. These are
    not HTTP attempt counts: SDK retries happen inside one invocation. Caller
    identity scopes are represented by opaque numbers in exported measurements.
    """

    def __init__(self) -> None:
        self.calls: Counter[tuple[MeasurementScope, str, str]] = Counter()
        self.clients_observed: Counter[tuple[MeasurementScope, str]] = Counter()
        self.collection_seconds: dict[tuple[MeasurementScope, str], list[float]] = {}
        self._clients: WeakKeyDictionary = WeakKeyDictionary()
        self._identities: dict[tuple[str, str], int] = {}
        self._closed = False
        self._lock = RLock()

    def __enter__(self) -> "ScanMeasurements":
        if self._closed:
            raise RuntimeError("Measurements are already closed")
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def instrument(self, client: BaseClient, account_id: str, identity: str) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Measurements are already closed")
            scope = MeasurementScope(account_id, identity, client.meta.region_name)
            if client in self._clients:
                if self._clients[client][0] != scope:
                    raise ValueError("A measured client cannot change identity scope")
                return
            service = client.meta.service_model.service_name
            event = "before-parameter-build.*.*"
            handler_id = f"awsherlock-measurements-{id(self)}"

            def count(model: OperationModel, **kwargs: object) -> None:
                with self._lock:
                    self.calls[scope, service, model.name] += 1

            client.meta.events.register(event, count, unique_id=handler_id)
            self._clients[client] = (scope, event, handler_id)
            self.clients_observed[scope, service] += 1
            self._identities.setdefault((account_id, identity), len(self._identities) + 1)

    @contextmanager
    def collection(self, account_id: str, identity: str, region: str | None,
                   service: str) -> Iterator[None]:
        with self._lock:
            if self._closed:
                raise RuntimeError("Measurements are already closed")
            scope = MeasurementScope(account_id, identity, region)
            self._identities.setdefault((account_id, identity), len(self._identities) + 1)
        started = perf_counter()
        try:
            yield
        finally:
            elapsed = perf_counter() - started
            with self._lock:
                self.collection_seconds.setdefault((scope, service), []).append(elapsed)

    def close(self) -> None:
        with self._lock:
            clients = list(self._clients.items())
            self._closed = True
        for client, (_, event, handler_id) in clients:
            client.meta.events.unregister(event, unique_id=handler_id)
        with self._lock:
            self._clients.clear()

    def to_dict(self) -> dict:
        with self._lock:
            identities = {key: index + 1 for index, key in enumerate(sorted(self._identities))}
            calls = list(self.calls.items())
            clients = list(self.clients_observed.items())
            collections = [(key, list(samples)) for key, samples in self.collection_seconds.items()]

        def fields(scope: MeasurementScope, service: str) -> dict:
            return {"account_id": scope.account_id,
                    "identity_scope": identities[scope.account_id, scope.identity],
                    "region": scope.region, "service": service}

        def scope_key(scope: MeasurementScope, service: str) -> tuple:
            return (scope.account_id, identities[scope.account_id, scope.identity],
                    scope.region or "", service)

        return {
            "schema_version": 1,
            "call_unit": "SDK invocation (not HTTP attempts or retries)",
            "client_unit": "distinct instrumented SDK client",
            "authentication_calls_included": False,
            "calls": [{**fields(scope, service), "operation": operation, "count": count}
                      for (scope, service, operation), count in sorted(
                          calls, key=lambda item: (*scope_key(item[0][0], item[0][1]), item[0][2]))],
            "clients": [{**fields(scope, service), "count": count}
                        for (scope, service), count in sorted(
                            clients, key=lambda item: scope_key(item[0][0], item[0][1]))],
            "collections": [{**fields(scope, service), "seconds": samples}
                            for (scope, service), samples in sorted(
                                collections, key=lambda item: scope_key(item[0][0], item[0][1]))],
        }
