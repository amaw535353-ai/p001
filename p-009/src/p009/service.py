"""Private bounded OTLP JSON archive sink and tenant-scoped investigation API."""

import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import BoundedSemaphore

from p009.archive import Archive
from p009.auth import Authenticator
from p009.config import config
from p009.correlate import KEYS, timeline
from p009.ingest import Pipeline
from p009.models import Event, Principal
from p009.safety import ROOT, Denied, Invalid, canonical, digest, parse


def attributes(values):
    return {v["key"]: next(iter(v.get("value", {}).values()), None) for v in values}


def nanos(stamp) -> str:
    return datetime.fromtimestamp(int(stamp) / 1_000_000_000, timezone.utc).isoformat()


def otlp_events(value: dict, signal: str):
    if signal == "traces":
        for resource in value.get("resourceSpans", []):
            for scope in resource.get("scopeSpans", []):
                for span in scope.get("spans", []):
                    attrs = attributes(span.get("attributes", []))
                    kind = attrs.get("p009.event_type", "request")
                    event = {
                        "event_id": "span-" + span["spanId"],
                        "event_type": kind,
                        "event_time": nanos(span["startTimeUnixNano"]),
                        "trace_id": span["traceId"],
                        "span_id": span["spanId"],
                        "operation": "synthetic-observe",
                    }
                    if span.get("parentSpanId"):
                        event["parent_span_id"] = span["parentSpanId"]
                    for key in (
                        "request_id",
                        "tool_call_id",
                        "authorization_decision_id",
                        "model_ref",
                        "decision",
                    ):
                        if attrs.get("p009." + key) is not None:
                            event[key] = attrs["p009." + key]
                    if span.get("status", {}).get("code") == 2:
                        event["outcome"] = "error"
                    yield event
    elif signal == "logs":
        for resource in value.get("resourceLogs", []):
            for scope in resource.get("scopeLogs", []):
                for log in scope.get("logRecords", []):
                    attrs = attributes(log.get("attributes", []))
                    yield {
                        "event_id": attrs["p009.event_id"],
                        "event_type": attrs.get("p009.event_type", "security"),
                        "event_time": nanos(log["timeUnixNano"]),
                        "signal": attrs.get("p009.signal", "pipeline"),
                        "decision": attrs.get("p009.decision", "unknown"),
                        "request_id": attrs.get("p009.request_id"),
                    }
    elif signal == "metrics":
        for resource in value.get("resourceMetrics", []):
            for scope in resource.get("scopeMetrics", []):
                for metric in scope.get("metrics", []):
                    data = metric.get("gauge", metric.get("sum", {}))
                    for point in data.get("dataPoints", []):
                        yield {
                            "event_id": "metric-" + digest(point)[:24],
                            "event_type": "metric",
                            "event_time": nanos(point["timeUnixNano"]),
                            "signal": "synthetic-request-count",
                            "value": float(point.get("asDouble", point.get("asInt", 0))),
                        }
    else:
        raise Invalid("OTLP-SIGNAL")


def serve():
    cfg = config()
    archive = Archive(
        ROOT / ".runtime/archive", digest(cfg), os.environ.get("P009_DEPLOYMENT_DIGEST", "0" * 64)
    )
    pipeline = Pipeline(archive, cfg)
    producer = Principal(actor="collector", tenant="tenant-a", role="producer")
    operator = Principal(actor="operator-a", tenant="tenant-a", role="exporter")
    viewer_b = Principal(actor="operator-b", tenant="tenant-b", role="viewer")
    auth = Authenticator(
        {
            os.environ["P009_COLLECTOR_TOKEN"]: producer,
            os.environ["P009_OPERATOR_TOKEN"]: operator,
            os.environ["P009_VIEWER_B_TOKEN"]: viewer_b,
        }
    )
    capacity = BoundedSemaphore(4)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, code, value):
            raw = canonical(value)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            try:
                if self.path == "/healthz":
                    return self.reply(200, {"status": "alive", "queued": len(pipeline.queue)})
                principal = auth.authenticate(self.headers.get("Authorization", ""))
                if self.path == "/status":
                    archive.authorize(principal, "read")
                    rows = archive.records(principal)
                    return self.reply(
                        200,
                        {
                            "events": len(rows),
                            "counters": dict(pipeline.metrics),
                            "integrity": archive.verify()["status"],
                            "queue": len(pipeline.queue),
                        },
                    )
                self.reply(404, {"error": "UNKNOWN-PATH"})
            except (ValueError, OSError):
                self.reply(403, {"error": "ACCESS-REFUSED"})

        def do_POST(self):
            if not capacity.acquire(blocking=False):
                return self.reply(429, {"error": "CONCURRENCY-BOUND"})
            try:
                self.connection.settimeout(5)
                principal = auth.authenticate(self.headers.get("Authorization", ""))
                length = self.headers.get("Content-Length", "")
                if (
                    not length.isdigit()
                    or not 0 < int(length) <= cfg.max_payload
                    or self.headers.get("Transfer-Encoding")
                ):
                    return self.reply(413, {"error": "PAYLOAD-BOUND"})
                value = parse(self.rfile.read(int(length)))
                if self.path in {"/v1/traces", "/v1/logs", "/v1/metrics"}:
                    if principal.role != "producer":
                        raise Denied("PRODUCER-REQUIRED")
                    rows = list(otlp_events(value, self.path.split("/")[-1]))
                    if len(rows) > cfg.max_batch:
                        raise Invalid("OTLP-BATCH-BOUND")
                    pipeline.batch("otel-a", canonical(rows), principal, "collector-observed")
                    pipeline.flush()
                    return self.reply(200, {})
                if self.path == "/timeline":
                    if len(value) != 1 or next(iter(value)) not in KEYS:
                        raise Invalid("QUERY-INVALID")
                    rows = [Event.model_validate(e) for e in archive.records(principal)]
                    result = timeline(rows, principal, query=value)
                    return self.reply(200, result.model_dump(mode="json"))
                self.reply(404, {"error": "UNKNOWN-PATH"})
            except (ValueError, KeyError, TypeError, OSError):
                pipeline.metrics["http_rejected"] += 1
                self.reply(400, {"error": "REQUEST-REFUSED"})
            finally:
                capacity.release()

    class BoundedServer(ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 8
        workers = BoundedSemaphore(4)

        def process_request(self, request, client_address):
            request.settimeout(5)
            if not self.workers.acquire(blocking=False):
                request.sendall(b"HTTP/1.0 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n")
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except Exception:
                self.workers.release()
                raise

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                self.workers.release()

        def handle_error(self, request, client_address):
            pipeline.metrics["connection_error"] += 1

    BoundedServer(("0.0.0.0", 8090), Handler).serve_forever()


if __name__ == "__main__":
    serve()
