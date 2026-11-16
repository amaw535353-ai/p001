"""Load mounted credentials inside the process, never through command arguments."""

import asyncio
import json
import os
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from p006.adapters import Gateway, Policy, Vault
from p006.identity import Identity
from p006.models import Profile, digest
from p006.pep import Engine, create_app
from p006.transport import Transport

ROOT = Path("/app")
SECRETS = Path("/run/p006")


def main():
    mode = os.environ.get("P006_COMPONENT", "pep")
    if mode == "webui":
        env = json.loads((SECRETS / "environment.json").read_text())
        os.environ.update(env)
        # Preserve the product's upstream branding and license.
        os.execv("/bin/bash", ["bash", "/app/backend/start.sh"])
    if mode == "gateway":
        async def credential():
            http = Transport()
            try:
                return await Vault(http, json.loads((SECRETS / "approle.json").read_text()), "p006-gateway").read()
            finally:
                await http.client.aclose()
        secret = asyncio.run(credential())
        os.environ["P006_MODEL_KEY"] = secret["provider_key"]
        import secrets
        os.environ["LITELLM_MASTER_KEY"] = secrets.token_urlsafe(48)
        os.execvp("litellm", ["litellm", "--config", "/app/gateway/litellm/config.yaml", "--port", "4000",
                              "--host", "0.0.0.0", "--num_workers", "1"])
    if mode == "weak":
        from p006.weak import create_app as weak_app
        uvicorn.run(weak_app(), host="0.0.0.0", port=8080, access_log=False, log_level="warning")
        return
    if mode == "model":
        import hmac
        app = FastAPI(docs_url=None, openapi_url=None, redoc_url=None)
        @app.get("/healthz")
        async def health():
            return {"status": "alive", "model": "deterministic-synthetic"}
        @app.post("/v1/chat/completions")
        async def model(request: Request):
            if not hmac.compare_digest(request.headers.get("authorization", ""),
                                       "Bearer " + (SECRETS / "provider-key").read_text()):
                return JSONResponse({"error": "MODEL_DENIED"}, status_code=403)
            body = await request.body()
            if len(body) > 20000:
                return JSONResponse({"error": "SIZE"}, status_code=413)
            data = await request.json()
            return {"id": "p006-local", "object": "chat.completion", "created": 1,
                    "model": "p006-deterministic", "choices": [{"index": 0, "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "P006 synthetic response "
                                    + digest(data.get("messages", []))[:16]}}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
        uvicorn.run(app, host="0.0.0.0", port=8000, access_log=False, log_level="warning")
        return
    profile = Profile.model_validate_json((ROOT / "config/hardened.json").read_text())
    http = Transport()
    identity = Identity(profile, http, (SECRETS / "introspection-secret").read_text())
    engine = Engine(profile, identity, Policy(http),
                    Vault(http, json.loads((SECRETS / "approle.json").read_text())), Gateway(http))
    import logging
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    uvicorn.run(create_app(engine), host="0.0.0.0", port=8080, access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
