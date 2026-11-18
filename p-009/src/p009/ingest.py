"""Bounded pre-persistence ingestion with observable rejection/backpressure counters."""

from collections import Counter, deque
from threading import Lock

from p009.archive import Archive
from p009.config import Config
from p009.models import Principal
from p009.normalize import normalize
from p009.safety import Denied, Invalid, canonical, parse


class Pipeline:
    def __init__(self, archive: Archive, config: Config):
        self.archive, self.config = archive, config
        self.queue: deque = deque()
        self.metrics: Counter = Counter()
        self.lock = Lock()

    def submit(self, source_id: str, value: dict, principal: Principal, provenance="source-adapter"):
        try:
            self._enqueue([self._prepare(source_id, value, principal, provenance)], principal)
        except (ValueError, TypeError):
            self.metrics["rejected"] += 1
            raise Invalid("INGEST-REFUSED") from None

    def _prepare(self, source_id, value, principal, provenance):
        self.archive.authorize(principal, "ingest")
        source = self.config.source(source_id)
        if source.tenant_ref != principal.tenant:
            raise Denied("SOURCE-TENANT-DENIED")
        if len(canonical(value)) > self.config.max_payload:
            raise Invalid("PAYLOAD-BOUND")
        return normalize(source, value, provenance)

    def _enqueue(self, events, principal):
        with self.lock:
            if len(self.queue) + len(events) > self.config.queue_size:
                self.metrics["queue_full"] += 1
                self.metrics["queue_rejected_events"] += len(events)
                raise Invalid("QUEUE-FULL")
            self.queue.extend((event, principal) for event in events)
            self.metrics["accepted"] += len(events)
            self.metrics["redacted_fields"] += sum(e.redacted_fields for e in events)

    def batch(self, source_id: str, raw: bytes, principal: Principal, provenance="source-adapter"):
        try:
            if len(raw) > self.config.max_payload:
                raise Invalid("PAYLOAD-BOUND")
            value = parse(raw)
            if not isinstance(value, list) or len(value) > self.config.max_batch:
                raise Invalid("BATCH-BOUND")
            events = [self._prepare(source_id, row, principal, provenance) for row in value]
            self._enqueue(events, principal)
        except (ValueError, TypeError):
            self.metrics["rejected"] += 1
            raise Invalid("BATCH-REFUSED") from None

    def flush(self):
        results = []
        with self.lock:
            while self.queue:
                event, principal = self.queue[0]
                try:
                    result = self.archive.put_event(event, principal)
                except (ValueError, OSError):
                    self.metrics["export_failed"] += 1
                    # Retain the sanitized head for explicit retry; never silently discard.
                    raise Invalid("ARCHIVE-EXPORT-FAILED") from None
                self.queue.popleft()
                self.metrics[result["status"].lower()] += 1
                results.append(result)
        return results
