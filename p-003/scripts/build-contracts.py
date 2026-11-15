#!/usr/bin/env python3
"""Deterministically regenerate P-003 schemas and synthetic draft fixtures."""
import json
from pathlib import Path

from p003 import demo, models
from p003.util import ROOT


def strict_digests(value):
    if isinstance(value, dict):
        props = value.get("properties", {})
        if "content_digest" in props:
            props["content_digest"] = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
            value["required"] = sorted(set(value.get("required", [])) | {"content_digest"})
        for item in value.values():
            strict_digests(item)
    elif isinstance(value, list):
        for item in value:
            strict_digests(item)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


for name, cls in {
    "engagement": models.Engagement, "asset": models.Asset, "scope": models.Scope,
    "roe": models.ROE, "authorization": models.Authorization, "decision": models.Decision,
    "events": models.Event, "review-evidence": models.ReviewEvidence,
    "evidence-policy": models.EvidencePolicy, "amendment": models.Amendment,
    "stop-event": models.StopEvent, "exception": models.ExceptionRecord,
    "client": models.Client, "check-request": models.CheckRequest,
    "engagement-policy": models.PolicyManifest, "evidence-manifest": models.EvidenceManifest,
}.items():
    schema = cls.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://p003.example.test/schemas/1.0/" + name + ".schema.json"
    strict_digests(schema)
    write(ROOT / "schemas" / (name + ".schema.json"), schema)

first = demo.engagement()
second = demo.extension(first)
write(ROOT / "examples/engagement-draft-a.json", first.model_dump(mode="json"))
write(ROOT / "examples/engagement-expired-b.json", demo.engagement("B").model_dump(mode="json"))
write(ROOT / "examples/scope-extension-v2.json", second.model_dump(mode="json"))
write(ROOT / "examples/check-allow.json", demo.request())
write(ROOT / "examples/check-deny-unknown-path.json", demo.request(
    target={"kind": "url", "value": "http://127.0.0.1:8000/out-of-scope"}))
write(ROOT / "examples/review-a-v1.json", demo.review(first).model_dump(mode="json"))
write(ROOT / "examples/review-a-v2.json", demo.review(second).model_dump(mode="json"))
