import pytest

from p003 import demo
from p003.store import Store


@pytest.fixture
def draft(tmp_path):
    store = Store(tmp_path / "owned", create=True)
    spec = demo.engagement()
    store.create(spec)
    demo.install_review(store, spec)
    return store


@pytest.fixture
def active(draft):
    draft.transition("ENG-DEMO-A", "demo-a-requestor", "submit", version=1, at="2026-11-15T08:10:00Z")
    spec = draft.read("ENG-DEMO-A", "demo-a-reviewer").spec
    draft.transition(
        "ENG-DEMO-A",
        "demo-a-reviewer",
        "approve",
        version=1,
        at="2026-11-15T08:20:00Z",
        simulate_review=True,
        expected_digest=spec.content_digest,
        evidence_ref="training-review-a-v1",
    )
    draft.transition("ENG-DEMO-A", "demo-a-owner", "activate", version=1, at="2026-11-15T09:00:00Z")
    return draft
