"""Metadata-only Langfuse v4 reference inspection on an explicit loopback binding."""

import base64
import http.client
import os
from datetime import timedelta
from typing import Any
from urllib.parse import quote, urlencode

from p010.models import ID, SourceRecord, Strict, TraceReference
from p010.safety import HASH_LIMIT, Invalid, parse, privacy_check, select, timestamp
from p010.store import validate
from p010.workflow import Workflow

VERSION = "4.80.0"
ENDPOINT = "/api/public/v2/observations"
MAX_REPLY = 256 * 1024


class Binding(Strict):
    project_ref: ID
    project_id: ID


def from_event(flow: Workflow, source_id: str, event_id: str, project_ref: str) -> TraceReference:
    source = flow.current("source", source_id).as_type(SourceRecord)
    if source.contract != "p009-handoff-v1":
        raise Invalid("A P-009 handoff is required")
    event = next((row for row in source.payload["event_references"] if row["event_id"] == event_id), None)
    if not event or not event.get("trace_id"):
        raise Invalid("The exact P-009 event has no trace reference")
    return validate(
        TraceReference,
        {
            "trace_id": event["trace_id"],
            "observation_id": event.get("span_id"),
            "source_time": event["event_time"],
            "project_ref": project_ref,
            "source": "p009-handoff",
        },
    )


def _get(port: int, target: str, authorization: str | None = None) -> dict:
    if type(port) is not int or not 1024 <= port <= 65535:
        raise Invalid("A numeric local Langfuse port above 1023 is required")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    request = {"Accept": "application/json"}
    if authorization:
        request["Authorization"] = authorization
    try:
        conn.request("GET", target, headers=request)
        reply = conn.getresponse()
        if reply.status != 200:
            raise Invalid("Langfuse read unavailable or refused")
        value = parse(reply.read(MAX_REPLY + 1), limit=MAX_REPLY)
    except (OSError, http.client.HTTPException):
        raise Invalid("Langfuse loopback service unavailable") from None
    finally:
        conn.close()
    if not isinstance(value, dict):
        raise Invalid("Invalid Langfuse response shape")
    return value


def _env_auth() -> str:
    public = os.environ.get("P010_LANGFUSE_PUBLIC_KEY", "")
    secret = os.environ.get("P010_LANGFUSE_SECRET_KEY", "")
    if not (12 <= len(public) <= 256 and 12 <= len(secret) <= 256) or not all(
        value.isascii() and all(char.isalnum() or char in "-_" for char in value)
        for value in (public, secret)
    ):
        raise Invalid("Langfuse project credentials are unavailable or malformed")
    return "Basic " + base64.b64encode(f"{public}:{secret}".encode()).decode("ascii")


def _inspect(
    reference: TraceReference,
    port: int,
    binding: Binding,
    get=_get,  # Test doubles exercise the parsed protocol without network access.
) -> dict[str, Any]:
    if binding.project_ref != reference.project_ref:
        raise Invalid("Langfuse reference does not match the selected project")
    if get(port, "/api/public/health").get("version") != VERSION:
        raise Invalid("Deployed Langfuse version does not match the verified API")
    auth = _env_auth()
    stamp = timestamp(reference.source_time)
    query = {
        "traceId": reference.trace_id,
        "limit": "30",
        "fields": "time",
        "fromStartTime": (stamp - timedelta(minutes=2)).isoformat(),
        "toStartTime": (stamp + timedelta(minutes=2)).isoformat(),
    }
    seen = set()
    verified: list[dict] = []
    for _ in range(4):
        response = get(port, ENDPOINT + "?" + urlencode(query), auth)
        data, meta = response.get("data"), response.get("meta")
        if not isinstance(data, list) or len(data) > 30 or not isinstance(meta, dict):
            raise Invalid("Invalid Langfuse observation reply")
        for row in data:
            if (
                not isinstance(row, dict)
                or row.get("traceId") != reference.trace_id
                or row.get("projectId") != binding.project_id
            ):
                raise Invalid("Langfuse trace or project mismatch")
            observed = validate(
                TraceReference,
                {
                    **reference.model_dump(),
                    "observation_id": row.get("id"),
                    "source_time": row.get("startTime"),
                },
            )
            if observed.observation_id is None or abs(timestamp(observed.source_time) - stamp) > timedelta(
                minutes=2
            ):
                raise Invalid("Langfuse observation ID or time does not match")
            if reference.observation_id is None or observed.observation_id == reference.observation_id:
                verified.append(
                    {"observation_id": observed.observation_id, "source_time": observed.source_time}
                )
        if verified:
            result = {
                "status": "OBSERVED_REFERENCE",
                "instance_version": VERSION,
                "observations": verified,
                "local_link": f"http://127.0.0.1:{port}/project/{quote(binding.project_id, safe='')}/traces/{reference.trace_id}",
            }
            privacy_check(result)
            return result
        cursor = meta.get("cursor")
        if cursor is None:
            break
        if not isinstance(cursor, str) or len(cursor) > 2048 or cursor in seen:
            raise Invalid("Invalid Langfuse pagination")
        seen.add(cursor)
        query["cursor"] = cursor
    raise Invalid("Trace reference was not observed within the requested project and time range")


def show(reference: TraceReference, *, port: int | None = None, binding: Binding | None = None) -> dict:
    base = {
        "reference": reference.model_dump(mode="json"),
        "redaction": "METADATA_ONLY",
        "limitations": [HASH_LIMIT, "Trace completeness and independent evidence custody are unverified."],
    }
    if port is None:
        return {**base, "status": "REFERENCE_ONLY", "live_api": "NOT_TESTED"}
    if binding is None:
        raise Invalid("Explicit Langfuse project binding is required")
    try:
        return {**base, **_inspect(reference, port, binding)}
    except Invalid as error:
        return {**base, "status": "REFERENCE_ONLY", "live_api": "BLOCKED", "reason": str(error)}


def source_record(record_id: str, reference: TraceReference, observation: dict, at: str) -> SourceRecord:
    return validate(
        SourceRecord,
        {
            "project": "Langfuse",
            "contract": "p010-langfuse-reference-1.0",
            "source_version": observation.get("instance_version", "unverified"),
            "source_record_id": record_id,
            "source_time": reference.source_time,
            "imported_at": at,
            "validation": "REFERENCE_ONLY",
            "payload": {
                **reference.model_dump(mode="json"),
                **select(observation, "status instance_version live_api observations local_link redaction"),
            },
            "limitations": observation["limitations"],
            "omissions": ["Trace inputs, outputs, metadata, user/session fields and credentials"],
        },
    )
