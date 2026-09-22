"""Opt-in scan-local SDK invocation counts; never inspect API payloads."""

from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
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

    def __enter__(self) -> "ScanMeasurements":
        if self._closed:
            raise RuntimeError("Measurements are already closed")
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def instrument(self, client: BaseClient, account_id: str, identity: str) -> None:
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
            self.calls[scope, service, model.name] += 1

        client.meta.events.register(event, count, unique_id=handler_id)
        self._clients[client] = (scope, event, handler_id)
        self.clients_observed[scope, service] += 1
        self._identities.setdefault((account_id, identity), len(self._identities) + 1)

    @contextmanager
    def collection(self, account_id: str, identity: str, region: str | None,
                   service: str) -> Iterator[None]:
        if self._closed:
            raise RuntimeError("Measurements are already closed")
        scope = MeasurementScope(account_id, identity, region)
        self._identities.setdefault((account_id, identity), len(self._identities) + 1)
        started = perf_counter()
        try:
            yield
        finally:
            self.collection_seconds.setdefault((scope, service), []).append(perf_counter() - started)

    def close(self) -> None:
        for client, (_, event, handler_id) in list(self._clients.items()):
            client.meta.events.unregister(event, unique_id=handler_id)
        self._clients.clear()
        self._closed = True

    def to_dict(self) -> dict:
        def fields(scope: MeasurementScope, service: str) -> dict:
            return {"account_id": scope.account_id,
                    "identity_scope": self._identities[scope.account_id, scope.identity],
                    "region": scope.region, "service": service}

        return {
            "schema_version": 1,
            "call_unit": "SDK invocation (not HTTP attempts or retries)",
            "client_unit": "distinct instrumented SDK client",
            "authentication_calls_included": False,
            "calls": [{**fields(scope, service), "operation": operation, "count": count}
                      for (scope, service, operation), count in self.calls.items()],
            "clients": [{**fields(scope, service), "count": count}
                        for (scope, service), count in self.clients_observed.items()],
            "collections": [{**fields(scope, service), "seconds": list(samples)}
                            for (scope, service), samples in self.collection_seconds.items()],
        }
