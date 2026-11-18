import pytest

from p009.correlate import identity, timeline
from p009.safety import Denied, Invalid


@pytest.mark.parametrize(
    "key,value",
    [
        ("trace_id", "a" * 32),
        ("request_id", "request-one"),
        ("tool_call_id", "tool-one"),
        ("authorization_decision_id", "decision-one"),
        ("test_id", "test-one"),
        ("test_run_id", "run-one"),
        ("evaluation_run_id", "evaluation-one"),
        ("alert_id", "alert-one"),
    ],
)
def test_exact_identifier_link(key, value, event, operator):
    rows = [event("one", **{key: value}), event("two", **{key: value})]
    result = timeline(rows, operator, query={key: value})
    assert len(result.links) == 1 and len(result.events) == 2
    assert all(s == "exact" for s in result.statuses.values())


def test_time_proximity_never_joins(event, operator):
    result = timeline([event("one"), event("two")], operator)
    assert not result.links and set(result.statuses.values()) == {"unmatched"}


def test_mixed_utc_formats_sort_by_actual_time(event, operator):
    first = event("first", event_time="2026-11-16T12:00:00Z")
    second = event("second", event_time="2026-11-16T12:00:00.100+00:00")
    result = timeline([second, first], operator)
    assert [e.event_id for e in result.events] == ["first", "second"]
    assert result.events[0].event_time == "2026-11-16T12:00:00Z"


def test_cross_tenant_join_refused(event, operator):
    with pytest.raises(Denied):
        timeline(
            [event("one", trace_id="a" * 32), event("two", source="synthetic-b", trace_id="a" * 32)], operator
        )


def test_ambiguous_request_does_not_create_link(event, operator):
    rows = [
        event("one", request_id="same", trace_id="a" * 32),
        event("two", request_id="same", trace_id="b" * 32),
    ]
    result = timeline(rows, operator)
    assert not result.links and set(result.statuses.values()) == {"ambiguous"}


def test_missing_event_and_sequence_are_gaps(event, operator):
    rows = [event("one", sequence=1), event("two", sequence=3)]
    result = timeline(rows, operator)
    assert result.missing_sequences == [2] and "completion" in result.missing_types
    assert len(result.events) == 2


def test_out_of_order_preserves_source_and_observed_time(event, operator):
    rows = [event("one"), event("two", event_time="2026-11-16T11:59:00Z")]
    result = timeline(rows, operator)
    assert result.out_of_order == [identity(rows[1])]
    assert result.events[0].event_time == rows[1].event_time


def test_clock_skew_is_visible(event, operator):
    row = event("one", event_time="2026-11-16T11:00:00Z")
    assert timeline([row], operator).clock_skew == [identity(row)]


def test_missing_p006_request_id_stays_partial(event, operator):
    row = event("one", event_type="authorization", authorization_decision_id="decision-one")
    result = timeline([row], operator)
    assert result.statuses[identity(row)] == "partial" and row.request_id is None


def test_alert_links_only_to_unique_original_event(event, operator):
    rows = [
        event("security-one", event_type="security"),
        event("alert-one", event_type="alert", related_event_id="security-one"),
    ]
    result = timeline(rows, operator)
    assert len(result.links) == 1 and result.links[0].key == "related_event_id"


def test_unknown_query_key_refused(event, operator):
    with pytest.raises(Invalid):
        timeline([event()], operator, query={"actor_ref": "operator"})
