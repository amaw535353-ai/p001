"""Actual selected-product checks. Native outages stay explicit, never fixture passes."""

import json
import time
from uuid import uuid4

from p009.operate import compose, credentials, run, up
from p009.safety import ROOT, Blocked, canonical, write_new

# This client runs in the private archive namespace. It never uses a public preview.
PROBE = """import base64,json,os,sys,urllib.request,urllib.error
x=json.load(sys.stdin)
origins={"archive":"http://archive:8090", "collector":"http://collector:4318", "health":"http://collector:13133", "metrics":"http://collector:8888", "langfuse":"http://langfuse-web:3000"}
headers={"Content-Type": "application/json"}
kind=x.get("auth")
if kind in {"operator","producer","other"}:
 key={"operator":"P009_OPERATOR_TOKEN","producer":"P009_COLLECTOR_TOKEN","other":"P009_VIEWER_B_TOKEN"}[kind]
 headers["Authorization"]="Bearer "+os.environ[key]
elif kind=="otlp":
 headers["Authorization"]="Basic "+base64.b64encode(("producer:"+os.environ["P009_OTLP_PASSWORD"]).encode()).decode()
elif kind=="langfuse":
 headers["Authorization"]="Basic "+base64.b64encode((os.environ["P009_LANGFUSE_PUBLIC_KEY"]+":"+os.environ["P009_LANGFUSE_SECRET_KEY"]).encode()).decode()
elif kind=="forged":headers["Authorization"]="Bearer forged"
raw=None if x.get("body") is None else json.dumps(x["body"]).encode()
if x.get("raw") is not None:raw=x["raw"].encode()
request=urllib.request.Request(origins[x["service"]]+x["path"],raw,headers,method=x.get("method","GET"))
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
 with opener.open(request,timeout=10) as response:result={"status":response.status,"body":response.read(1048576).decode()}
except urllib.error.HTTPError as error:result={"status":error.code,"body":error.read(4096).decode()}
except Exception:result={"status":0,"body":"UNREACHABLE"}
print(json.dumps(result))
"""


def probe(service, path, *, method="GET", body=None, auth=None, raw=None):
    values = {"service": service, "path": path, "method": method, "body": body, "auth": auth, "raw": raw}
    source = "exec(" + repr(PROBE) + ")"
    output = run(
        [
            "docker",
            "compose",
            "-f",
            str(ROOT / "compose.yaml"),
            "exec",
            "-T",
            "-e",
            "P009_OTLP_PASSWORD",
            "archive",
            "python",
            "-c",
            source,
        ],
        env=credentials(),
        input=json.dumps(values),
        timeout=30,
    )
    return json.loads(output)


def check(rows, name, description, function):
    try:
        observation = function()
        if observation is not True:
            raise AssertionError()
        rows.append({"id": name, "assertion": description, "status": "PASS", "observed": observation})
    except Blocked as error:
        rows.append({"id": name, "assertion": description, "status": "BLOCKED", "observed": str(error)})
    except Exception as error:
        rows.append(
            {"id": name, "assertion": description, "status": "FAIL", "observed": type(error).__name__}
        )


def wait_ready():
    for _ in range(30):
        try:
            if probe("archive", "/healthz")["status"] == 200 and probe("health", "/")["status"] == 200:
                return
        except Blocked:
            pass
        time.sleep(0.5)
    raise Blocked("CORE-READINESS-TIMEOUT")


def synthetic(fail=False):
    args = ["exec", "-T", "-e", "P009_OTLP_PASSWORD", "archive", "python", "-m", "p009.synthetic"]
    if fail:
        args += ["fail"]
    output = compose(*args, timeout=60)
    return json.loads(next(line for line in reversed(output.splitlines()) if line.startswith("{")))


def core_checks(rows=None):
    rows = rows if rows is not None else []
    running = run(["docker", "ps", "--filter", "label=io.p009.owner=p009", "--format", "{{.Names}}"])
    if not all(
        name in running.splitlines()
        for name in ("p009-archive-1", "p009-collector-1", "p009-model-backend-1")
    ):
        up("core")
    wait_ready()
    check(
        rows,
        "T09",
        "Actual Collector health endpoint responds",
        lambda: probe("health", "/")["status"] == 200,
    )
    check(
        rows,
        "T02",
        "Malformed OTLP JSON rejected",
        lambda: probe("collector", "/v1/traces", method="POST", raw="{", auth="otlp")["status"] == 400,
    )
    check(
        rows,
        "AUTH01",
        "OTLP producer authentication enforced",
        lambda: probe("collector", "/v1/traces", method="POST", body={}, auth="forged")["status"] == 401,
    )
    result = synthetic()
    time.sleep(2)
    response = probe(
        "archive", "/timeline", method="POST", body={"trace_id": result["trace_id"]}, auth="operator"
    )
    data = json.loads(response["body"])
    events = data.get("events", [])
    write_new(
        ROOT / ".runtime/live-artifacts" / ("trace-" + uuid4().hex + ".json"),
        canonical({"executed_source": result, "timeline": data, "collector": "0.165.0", "sdk": "0.63.0"}),
    )
    check(
        rows,
        "O-SOURCE",
        "SDK output checked before first network exporter",
        lambda: (
            result.get("source_privacy", {}).get("spans", 0) >= 5
            and result.get("source_privacy", {}).get("privacy_refused", -1) == 0
        ),
    )
    check(rows, "T01", "Executed spans arrive through actual Collector", lambda: len(events) >= 6)
    check(
        rows,
        "O01",
        "OpenLLMetry executes model, authorization and tool path",
        lambda: (
            {e["event_type"] for e in events} >= {"request", "authorization", "tool", "model", "completion"}
        ),
    )
    check(
        rows,
        "O02",
        "Collector-observed provenance on received spans",
        lambda: bool(events) and all(e["provenance"] == "collector-observed" for e in events),
    )
    ids = {e["span_id"] for e in events}
    check(
        rows,
        "O03",
        "Real child spans retain parent IDs",
        lambda: len([e for e in events if e["parent_span_id"] in ids]) >= 5,
    )
    check(
        rows,
        "O04",
        "W3C context reaches independently executed backend",
        lambda: len([e for e in events if e["event_type"] == "model"]) == 2,
    )
    check(
        rows,
        "O05",
        "Executed arithmetic tool span is correlated",
        lambda: any(e["event_type"] == "tool" and e["tool_call_id"] for e in events),
    )
    check(
        rows,
        "O06",
        "Prompt content absent from stored event shape",
        lambda: bool(events) and all("prompt" not in e and "completion" not in e for e in events),
    )
    check(
        rows,
        "O07",
        "Planted source prompt absent after Collector and archive",
        lambda: "CANARY" not in response["body"] and bool(events),
    )
    check(
        rows,
        "T04",
        "Collector source mapped to trusted tenant",
        lambda: (
            bool(events) and all(e["source_id"] == "otel-a" and e["tenant_ref"] == "tenant-a" for e in events)
        ),
    )
    check(
        rows,
        "X10",
        "Other tenant cannot retrieve the same trace",
        lambda: (
            json.loads(
                probe(
                    "archive", "/timeline", method="POST", body={"trace_id": result["trace_id"]}, auth="other"
                )["body"]
            )["events"]
            == []
        ),
    )
    failed = synthetic(True)
    time.sleep(2)
    failed_data = json.loads(
        probe("archive", "/timeline", method="POST", body={"trace_id": failed["trace_id"]}, auth="operator")[
            "body"
        ]
    )
    check(
        rows,
        "O08",
        "Provider failure has safe error outcome",
        lambda: (
            any(e["outcome"] == "error" for e in failed_data.get("events", []))
            and "CANARY" not in canonical(failed_data).decode()
        ),
    )
    # Send metric and structured audit/security records through their actual Collector pipelines.
    stamp = str(time.time_ns())
    resource = {"attributes": [{"key": "service.name", "value": {"stringValue": "p009-synthetic"}}]}
    metric = {
        "resourceMetrics": [
            {
                "resource": resource,
                "scopeMetrics": [
                    {
                        "metrics": [
                            {
                                "name": "synthetic_count",
                                "gauge": {"dataPoints": [{"timeUnixNano": stamp, "asDouble": 1.0}]},
                            }
                        ]
                    }
                ],
            }
        ]
    }
    check(
        rows,
        "METRIC01",
        "Actual Collector accepts OTLP metrics",
        lambda: probe("collector", "/v1/metrics", method="POST", body=metric, auth="otlp")["status"] == 200,
    )
    for kind in ("security", "authorization"):
        log = {
            "resourceLogs": [
                {
                    "resource": resource,
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "timeUnixNano": stamp,
                                    "body": {"stringValue": "P009_LOG_CANARY"},
                                    "attributes": [
                                        {
                                            "key": "p009.event_id",
                                            "value": {"stringValue": "live-" + uuid4().hex},
                                        },
                                        {"key": "p009.event_type", "value": {"stringValue": kind}},
                                        {"key": "p009.signal", "value": {"stringValue": "event-replay"}},
                                    ],
                                }
                            ]
                        }
                    ],
                }
            ]
        }
        check(
            rows,
            "LOG-" + kind,
            "Actual Collector accepts structured " + kind,
            lambda value=log: (
                probe("collector", "/v1/logs", method="POST", body=value, auth="otlp")["status"] == 200
            ),
        )
    time.sleep(2)
    check(
        rows,
        "T08",
        "Actual Collector self metrics are observable",
        lambda: "otelcol_receiver_accepted_spans" in probe("metrics", "/metrics")["body"],
    )
    check(
        rows, "R05", "Collector restart preserves retained archive", lambda: restart_check(result["trace_id"])
    )
    return rows


def restart_check(trace_id):
    compose("restart", "collector", timeout=30)
    wait_ready()
    value = probe("archive", "/timeline", method="POST", body={"trace_id": trace_id}, auth="operator")
    return len(json.loads(value["body"]).get("events", [])) >= 6


def live(profile="core"):
    rows: list[dict] = []
    try:
        if profile == "core":
            core_checks(rows)
        else:
            from p009.products import product_checks

            product_checks(profile, rows)
    except Blocked as error:
        rows.append({"id": "PROFILE-" + profile, "status": "BLOCKED", "observed": str(error)})
    result = {
        "profile": profile,
        "checks": rows,
        "counts": {
            key: sum(r["status"] == key for r in rows) for key in ("PASS", "FAIL", "BLOCKED", "NOT_TESTED")
        },
    }
    write_new(ROOT / ".runtime/live" / (profile + "-" + uuid4().hex + ".json"), canonical(result))
    return result
