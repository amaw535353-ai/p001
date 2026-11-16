"""Authenticated deterministic local provider. Prompts never echo into responses/logs."""

import hashlib
import json
import secrets
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(docs_url=None, openapi_url=None, redoc_url=None)


@app.get("/healthz")
async def health():
    return {"status": "ready", "mode": "deterministic-local"}


@app.post("/v1/chat/completions")
async def complete(request: Request):
    key = Path("/run/p006/model-key").read_text().strip()
    if not secrets.compare_digest(request.headers.get("authorization", ""), f"Bearer {key}"):
        return JSONResponse({"error": "AUTHENTICATION_REQUIRED"}, status_code=401)
    body = await request.body()
    if len(body) > 32768:
        return JSONResponse({"error": "SIZE"}, status_code=413)
    data = json.loads(body)
    fingerprint = hashlib.sha256(json.dumps(data.get("messages"), sort_keys=True).encode()).hexdigest()[:16]
    return {"id": "p006-mock", "object": "chat.completion", "created": int(time.time()),
            "model": data.get("model", "synthetic"), "choices": [{"index": 0, "message": {
                "role": "assistant", "content": "P006 synthetic response " + fingerprint}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
