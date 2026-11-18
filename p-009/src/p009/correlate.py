"""Tenant-scoped exact identifier graph. Time and text never establish a link."""

from collections import defaultdict
from datetime import datetime
from typing import Literal

from p009.models import Event, Link, Principal, Timeline
from p009.safety import Denied, Invalid, digest

KEYS = (
    "trace_id",
    "request_id",
    "span_id",
    "tool_call_id",
    "authorization_decision_id",
    "test_id",
    "test_run_id",
    "evaluation_run_id",
    "alert_id",
)


def identity(event: Event) -> str:
    return digest([event.source_id, event.event_id])


def timeline(
    events: list[Event],
    principal: Principal,
    case_id="p009-case",
    query: dict | None = None,
    expected: tuple[str, ...] = ("request", "authorization", "tool", "completion"),
) -> Timeline:
    if any(e.tenant_ref != principal.tenant for e in events):
        raise Denied("CROSS-TENANT-TIMELINE")
    if query and (len(query) != 1 or next(iter(query)) not in KEYS):
        raise Invalid("QUERY-FIELD")
    buckets: dict = defaultdict(list)
    for e in events:
        for key in KEYS:
            if getattr(e, key):
                buckets[(key, getattr(e, key))].append(e)
    links: list[Link] = []
    ambiguous: set[str] = set()
    for (key, value), group in buckets.items():
        if key == "request_id" and len({e.trace_id for e in group if e.trace_id}) > 1:
            ambiguous.update(identity(e) for e in group)
            continue
        first = group[0]
        links.extend(Link(left=identity(first), right=identity(e), key=key, value=value) for e in group[1:])
    # A source event reference links only if unique and in the same tenant.
    by_id: dict = defaultdict(list)
    for e in events:
        by_id[e.event_id].append(e)
    for e in events:
        if e.related_event_id:
            matches = by_id[e.related_event_id]
            if len(matches) == 1:
                links.append(
                    Link(
                        left=identity(e),
                        right=identity(matches[0]),
                        key="related_event_id",
                        value=e.related_event_id,
                    )
                )
            elif len(matches) > 1:
                ambiguous.add(identity(e))
    selected = {identity(e) for e in events}
    if query:
        key, value = next(iter(query.items()))
        selected = {identity(e) for e in events if getattr(e, key) == value}
        changed = True
        while changed:
            before = len(selected)
            for link in links:
                if link.left in selected or link.right in selected:
                    selected.update((link.left, link.right))
            changed = len(selected) > before
    retained = [e for e in events if identity(e) in selected]
    links = [link for link in links if link.left in selected and link.right in selected]
    joined = {p for link in links for p in (link.left, link.right)}
    statuses: dict[str, Literal["ambiguous", "exact", "partial", "unmatched"]] = {
        identity(e): (
            "ambiguous"
            if identity(e) in ambiguous
            else "exact"
            if identity(e) in joined
            else "partial"
            if e.correlation_status == "partial"
            else "unmatched"
        )
        for e in retained
    }
    previous: dict[str, datetime] = {}
    out_of_order = []
    skew = []
    for e in retained:
        stamp = datetime.fromisoformat(e.event_time.replace("Z", "+00:00"))
        observed = datetime.fromisoformat(e.observed_time.replace("Z", "+00:00"))
        if e.source_id in previous and stamp < previous[e.source_id]:
            out_of_order.append(identity(e))
        previous[e.source_id] = stamp
        if abs((observed - stamp).total_seconds()) > 60:
            skew.append(identity(e))
    missing_sequences: list[int] = []
    for source in {e.source_id for e in retained}:
        values = sorted({e.sequence for e in retained if e.source_id == source and e.sequence is not None})
        if values:
            # Bounded window; no claim about sequences before/after the observed range.
            missing_sequences.extend(
                v for v in range(values[0], min(values[-1], values[0] + 5000)) if v not in values
            )
    return Timeline(
        case_id=case_id,
        tenant_ref=principal.tenant,
        events=sorted(
            retained,
            key=lambda e: (
                datetime.fromisoformat(e.event_time.replace("Z", "+00:00")),
                datetime.fromisoformat(e.observed_time.replace("Z", "+00:00")),
                e.source_id,
                e.event_id,
            ),
        ),
        links=links,
        statuses=statuses,
        missing_types=sorted(set(expected) - {e.event_type for e in retained}),
        missing_sequences=missing_sequences,
        out_of_order=out_of_order,
        clock_skew=skew,
        limitations=[
            "Exact shared IDs establish association, not causality or source authenticity.",
            "Source and collection clocks are untrusted; absence is not proof of nonoccurrence.",
            "P006 authorization has no request ID; no time-based join is made.",
        ],
    )
