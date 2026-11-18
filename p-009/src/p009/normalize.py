"""Identity comes from a trusted ingress binding, never resource/payload labels."""

from typing import Literal

from p009.models import Event, Source, now
from p009.privacy import metadata
from p009.safety import digest


def normalize(source: Source, payload: dict, provenance="source-adapter", observed_time=None) -> Event:
    event, omitted = metadata(payload)
    category: Literal["security", "metric", "health", "trace", "audit"] = (
        "security"
        if event.event_type in {"security", "alert"}
        else "metric"
        if event.event_type == "metric"
        else "health"
        if event.event_type == "health"
        else "trace"
        if event.span_id
        else "audit"
    )
    return Event(
        **event.model_dump(),
        event_category=category,
        event_severity=5 if event.decision == "deny" else 0,
        observed_time=observed_time or now(),
        **source.model_dump(),
        source_event_digest=digest(event),
        redacted_fields=omitted,
        provenance=provenance,
        correlation_status="partial"
        if event.event_type == "authorization" and not event.request_id and not event.trace_id
        else "unmatched",
    )
