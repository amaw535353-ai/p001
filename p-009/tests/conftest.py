import pytest

from p009.archive import Archive
from p009.config import config
from p009.models import Principal
from p009.normalize import normalize


@pytest.fixture
def cfg():
    return config()


@pytest.fixture
def archive(tmp_path):
    return Archive(tmp_path / "archive")


@pytest.fixture
def operator():
    return Principal(actor="operator-a", tenant="tenant-a", role="custodian")


@pytest.fixture
def producer():
    return Principal(actor="producer-a", tenant="tenant-a", role="producer")


@pytest.fixture
def event(cfg):
    def make(event_id="event-one", source="synthetic-a", **fields):
        return normalize(
            cfg.source(source),
            {"event_id": event_id, "event_type": "request", "event_time": "2026-11-16T12:00:00Z", **fields},
            "synthetic-fixture",
            observed_time="2026-11-16T12:00:00+00:00",
        )

    return make
