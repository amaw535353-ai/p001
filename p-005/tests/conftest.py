"""Every core test fails on socket/DNS use; child CLI guard is also installed."""

import socket
import sys

import pytest

from p005.evidence.safety import PROJECT
from p005.ingestion.fixtures import build


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("P005_TEST_NETWORK_DISABLED")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, denied)


@pytest.fixture
def model():
    return build(PROJECT / "fixtures/baseline/architecture.yaml")


@pytest.fixture
def py():
    return sys.executable
