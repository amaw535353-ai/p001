"""Opt-in local contrast: trusts tenant header and skips authorization. Synthetic only."""

import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

WARNING = "INTENTIONALLY INSECURE — LOCAL SYNTHETIC LAB ONLY"


def create_app():
    if os.environ.get("P006_WEAK_CONFIRM") != "local-synthetic-only":
        raise RuntimeError("weak profile requires explicit local-only opt-in")
    app = FastAPI(docs_url=None, openapi_url=None, redoc_url=None)

    @app.get("/")
    async def warning():
        return HTMLResponse(f"<h1>{WARNING}</h1><p>Synthetic tenant-header and missing model authorization demo.</p>")

    @app.get("/healthz")
    async def health():
        return {"profile": "vulnerable-lab", "warning": WARNING}

    @app.post("/v1/chat/completions")
    async def weak_chat(request: Request):
        body = await request.body()
        if len(body) > 16384:
            return JSONResponse({"error": "SIZE"}, status_code=413)
        data = await request.json()
        return {"warning": WARNING, "tenant": request.headers.get("X-Tenant-ID", "tenant-a"),
                "model": data.get("model"), "response": "synthetic weak authorization demonstration"}

    return app
