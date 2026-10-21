"""Prevent unit tests from contacting AWS or any other network service."""

import socket

import pytest

# Register shared fixtures centrally, with distinct names for service-specific
# contexts. Their original function scopes and owning module state are retained.
# Explicit exports are intentional pytest registrations, not unused imports.
from test_assume_role import sessions
from test_audit import context as audit_context
from test_cli_options import no_aws
from test_ec2 import context as ec2_context
from test_iam import context as iam_context
from test_identity import identity_context
from test_s3 import context as s3_context
from test_serverless import context as serverless_context
from test_session import session_factory
from test_snapshot import snapshot

__all__ = [
    "audit_context",
    "ec2_context",
    "iam_context",
    "identity_context",
    "no_aws",
    "s3_context",
    "serverless_context",
    "session_factory",
    "sessions",
    "snapshot",
]


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_connection(*args: object, **kwargs: object) -> None:
        pytest.fail("Unit tests must not access the network")

    monkeypatch.setattr(socket.socket, "connect", fail_connection)
    monkeypatch.setattr(socket.socket, "connect_ex", fail_connection)
    monkeypatch.setattr(socket, "create_connection", fail_connection)
