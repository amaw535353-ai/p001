"""Offline sockets/DNS denied; marked live tests permit numeric loopback only."""

import socket
import pytest
from p007.catalog import catalog, plan
from p007.evidence import run


@pytest.fixture(autouse=True)
def no_egress(request, monkeypatch):
    connect, resolve = socket.socket.connect, socket.getaddrinfo
    live = bool(request.node.get_closest_marker("live"))

    def connect_local(wire, address):
        if live and isinstance(address, tuple) and address[0] == "127.0.0.1":
            return connect(wire, address)
        raise AssertionError("NETWORK-DENIED-BEFORE-REQUEST")

    def resolve_local(host, *args, **kwargs):
        if live and host == "127.0.0.1":
            return resolve(host, *args, **kwargs)
        raise AssertionError("DNS-DENIED")

    monkeypatch.setattr(socket.socket, "connect", connect_local)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_local)
    monkeypatch.setattr(socket, "getaddrinfo", resolve_local)


@pytest.fixture
def case():
    return catalog().tests[0]


@pytest.fixture
def offline_run(tmp_path):
    return run(plan(), root=tmp_path / "runs")


@pytest.fixture
def network_context(tmp_path):
    from p007.authorization import Guard, P003Reader
    from p007.fixture import owned_fixture
    from p007.governance_demo import simulated_ledger

    with owned_fixture() as lease:
        selected = plan("local-fixture", "playwright", target=lease.target)
        store, ref = simulated_ledger(lease.target, tmp_path / "scope")
        yield lease, store, ref, Guard(lease.target, P003Reader(ref), lease, selected.tests[0]), selected
