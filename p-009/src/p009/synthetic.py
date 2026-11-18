"""Real executed OpenLLMetry workflow, tool and model spans; deterministic backend."""

import base64
import json
import os
from typing import cast
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

os.environ["TRACELOOP_TRACE_CONTENT"] = "false"
os.environ["TRACELOOP_TELEMETRY"] = "false"

from opentelemetry import trace  # noqa: E402
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # noqa: E402
from opentelemetry.propagate import extract, inject  # noqa: E402
from opentelemetry.trace import Status, StatusCode  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult  # noqa: E402
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator  # noqa: E402
from traceloop.sdk import Traceloop  # noqa: E402
from traceloop.sdk.decorators import task, tool, workflow  # noqa: E402

from p009.safety import canonical  # noqa: E402
from p009.privacy import assert_safe  # noqa: E402

OPENER = build_opener(ProxyHandler({}))
SOURCE_COUNTS = {"spans": 0, "privacy_refused": 0}


class GuardedExporter(SpanExporter):
    """Inspect SDK output before the first exporter/queue; fail closed on content."""

    def __init__(self, delegate):
        self.delegate = delegate

    def export(self, spans):
        try:
            for span in spans:
                attributes = dict(span.attributes or {})
                if any(
                    k in attributes
                    for k in (
                        "traceloop.entity.input",
                        "traceloop.entity.output",
                        "gen_ai.input.messages",
                        "gen_ai.output.messages",
                    )
                ):
                    raise ValueError("CONTENT-CAPTURE-REFUSED")
                assert_safe(
                    {
                        "attributes": attributes,
                        "name": span.name,
                        "status": span.status.description,
                        "events": [
                            {"name": e.name, "attributes": dict(e.attributes or {})} for e in span.events
                        ],
                    }
                )
            SOURCE_COUNTS["spans"] += len(spans)
        except ValueError:
            SOURCE_COUNTS["privacy_refused"] += len(spans)
            return SpanExportResult.FAILURE
        return self.delegate.export(spans)

    def shutdown(self):
        self.delegate.shutdown()


def init():
    auth = base64.b64encode(("producer:" + os.environ["P009_OTLP_PASSWORD"]).encode()).decode()
    Traceloop.init(
        app_name="p009-synthetic",
        telemetry_enabled=False,
        trace_content=False,
        disable_batch=True,
        instruments=set(),
        propagator=TraceContextTextMapPropagator(),
        exporter=GuardedExporter(
            OTLPSpanExporter(
                endpoint="http://collector:4318/v1/traces",
                headers={"Authorization": "Basic " + auth},
                timeout=5,
            )
        ),
        resource_attributes={"p009.source": "synthetic-a"},
    )


def annotate(kind, request_id, decision_id, tool_id):
    current = trace.get_current_span()
    for k, v in {
        "event_type": kind,
        "request_id": request_id,
        "authorization_decision_id": decision_id,
        "tool_call_id": tool_id,
        "model_ref": "deterministic-local",
        "decision": "allow",
    }.items():
        current.set_attribute("p009." + k, v)


@tool(name="synthetic_tool")
def execute_tool(request_id, decision_id, tool_id):
    annotate("tool", request_id, decision_id, tool_id)
    return sum([1, 2, 3])


@task(name="synthetic_authorization")
def authorize(request_id, decision_id, tool_id):
    annotate("authorization", request_id, decision_id, tool_id)
    return True


@task(name="synthetic_model")
def model(request_id, decision_id, tool_id, fail=False, prompt="P009_PROMPT_CANARY"):
    annotate("model", request_id, decision_id, tool_id)
    headers = {
        "Content-Type": "application/json",
        "X-Request-ID": request_id,
        "X-Decision-ID": decision_id,
        "X-Tool-ID": tool_id,
    }
    inject(headers)
    # Planted content exists only at the source; no decorator content capture is enabled.
    request = Request("http://model-backend:8091/infer", canonical({"prompt": prompt, "fail": fail}), headers)
    try:
        with OPENER.open(request, timeout=5) as response:
            return json.load(response)
    except Exception:
        trace.get_current_span().set_status(Status(StatusCode.ERROR, "synthetic-provider-failure"))
        return {"status": "error"}


@workflow(name="synthetic_request")
def request_path(fail=False):
    request_id, decision_id, tool_id = ["p009-" + uuid4().hex for _ in range(3)]
    annotate("request", request_id, decision_id, tool_id)
    authorize(request_id, decision_id, tool_id)
    execute_tool(request_id, decision_id, tool_id)
    model(request_id, decision_id, tool_id, fail, prompt="P009_PROMPT_CANARY")
    with trace.get_tracer("p009").start_as_current_span("synthetic_completion"):
        annotate("completion", request_id, decision_id, tool_id)
    current = trace.get_current_span().get_span_context()
    return {"request_id": request_id, "trace_id": f"{current.trace_id:032x}"}


def backend():
    init()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            size = int(self.headers.get("Content-Length", "0"))
            if self.path != "/infer" or not 0 < size < 4096:
                self.send_error(400)
                return
            # Read the source prompt, but never record its bytes.
            value = json.loads(self.rfile.read(size))
            with trace.get_tracer("p009-backend").start_as_current_span(
                "synthetic_backend", context=extract({k.lower(): v for k, v in self.headers.items()})
            ):
                annotate(
                    "model",
                    self.headers["X-Request-ID"],
                    self.headers["X-Decision-ID"],
                    self.headers["X-Tool-ID"],
                )
                if value.get("fail"):
                    trace.get_current_span().set_status(
                        Status(StatusCode.ERROR, "synthetic-provider-failure")
                    )
                raw = canonical({"status": "error" if value.get("fail") else "success", "result": 6})
                self.send_response(503 if value.get("fail") else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

    HTTPServer(("0.0.0.0", 8091), Handler).serve_forever()


if __name__ == "__main__":
    import sys

    if "backend" in sys.argv:
        backend()
    else:
        init()
        result = request_path("fail" in sys.argv)
        cast(TracerProvider, trace.get_tracer_provider()).force_flush()
        result["source_privacy"] = dict(SOURCE_COUNTS)
        print(json.dumps(result))
