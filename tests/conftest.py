"""Prevent unit tests from contacting AWS or any other network service."""

import socket

import pytest


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_connection(*args: object, **kwargs: object) -> None:
        pytest.fail("Unit tests must not access the network")

    monkeypatch.setattr(socket.socket, "connect", fail_connection)
    monkeypatch.setattr(socket.socket, "connect_ex", fail_connection)
    monkeypatch.setattr(socket, "create_connection", fail_connection)
