"""LiteLLM OSS custom auth: verify a short-lived proof bound to the whole request."""

import asyncio
import hmac
import json
import re
import time
from pathlib import Path

from fastapi import HTTPException, Request

from p006.adapters import Vault, seal
from p006.transport import Transport

seen: dict[str, float] = {}
lock = asyncio.Lock()


async def authorize(request: Request, api_key: str):
    # Import only in the LiteLLM process; the offline PEP never depends on its SDK.
    from litellm.proxy._types import UserAPIKeyAuth

    stage = "REQUEST"
    try:
        if request.url.path not in {"/chat/completions", "/v1/chat/completions"} or request.method != "POST":
            raise ValueError()
        raw = await request.body()
        if len(raw) > 20000:
            raise ValueError()
        body = json.loads(raw)
        if set(body) != {"model", "messages", "max_tokens", "temperature", "stream", "metadata"}:
            raise ValueError()
        if body["model"] not in {"local-basic", "local-admin"} or body["stream"] is not False:
            raise ValueError()
        if type(body["max_tokens"]) is not int or not 1 <= body["max_tokens"] <= 128:
            raise ValueError()
        metadata = body["metadata"]
        if set(metadata) != {"p006_subject", "p006_tenant", "decision_id", "policy_version"}:
            raise ValueError()
        if metadata["policy_version"] != "p006-authz-v1":
            raise ValueError()
        stamp = request.headers.get("X-P006-Time", "")
        nonce = request.headers.get("X-P006-Nonce", "")
        proof = request.headers.get("X-P006-Proof", "")
        if not re.fullmatch(r"[0-9]{10}", stamp) or abs(time.time() - int(stamp)) > 10:
            raise ValueError()
        if not re.fullmatch(r"[a-f0-9]{32}", nonce) or not re.fullmatch(r"[a-f0-9]{64}", proof):
            raise ValueError()
        stage = "VAULT"
        http = Transport()
        try:
            credential = await Vault(http, json.loads(Path("/run/p006/approle.json").read_text()), "p006-gateway").read()
        finally:
            await http.client.aclose()
        stage = "KEY"
        if not hmac.compare_digest(api_key or "", credential["gateway_key"]):
            raise ValueError()
        stage = "PROOF"
        if not hmac.compare_digest(proof, seal(credential["gateway_key"], body, nonce, stamp)):
            raise ValueError()
        stage = "NONCE"
        async with lock:
            now = time.time()
            for old in [key for key, value in seen.items() if value < now - 20]:
                del seen[old]
            if nonce in seen or len(seen) >= 1000:
                raise ValueError()
            seen[nonce] = now
        stage = "IDENTITY"
        return UserAPIKeyAuth(api_key="p006-proof-verified", user_id=metadata["p006_subject"],
                              team_id=metadata["p006_tenant"], user_role="internal_user",
                              models=[body["model"]])
    except Exception:
        raise HTTPException(status_code=403, detail="P006_GATEWAY_DENIED_" + stage) from None
