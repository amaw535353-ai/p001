"""Server-side enforcement on every application request, before gateway access."""

import asyncio
import json
import logging
import time
import uuid
from collections import defaultdict, deque
from typing import cast

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError

from p006.models import Action, AuthzRequest, Chat, Principal, Profile
from p006.transport import Denied

audit = logging.getLogger("p006.audit")


class Limits:
    """Single-process atomic sliding windows. Failed attempts consume rate budget."""
    def __init__(self, rate: int, tokens: int):
        self.rate = rate
        self.tokens = tokens
        self.users: dict[str, deque] = defaultdict(deque)
        self.tenants: dict[str, deque] = defaultdict(deque)
        self.lock = asyncio.Lock()

    async def reserve(self, principal: Principal, amount: int):
        async with self.lock:
            now = time.monotonic()
            user, tenant = self.users[principal.subject], self.tenants[principal.tenant]
            while user and user[0] < now - 60:
                user.popleft()
            while tenant and tenant[0][0] < now - 60:
                tenant.popleft()
            if len(user) >= self.rate or sum(x[1] for x in tenant) + amount > self.tokens:
                raise Denied("QUOTA_DENIED", 429)
            user.append(now)
            tenant.append((now, amount))


class Engine:
    def __init__(self, profile: Profile, identity, policy, vault, gateway):
        if profile.name != "hardened":
            raise ValueError("hardened engine requires hardened configuration")
        self.profile, self.identity, self.policy = profile, identity, policy
        self.vault, self.gateway = vault, gateway
        self.limits = Limits(profile.requests_per_minute, profile.tenant_tokens_per_minute)
        self.concurrent = asyncio.Semaphore(4)

    async def authorize(self, token: str, action: Action, model: str, resource_tenant: str | None,
                        amount: int = 0):
        principal = await self.identity.verify(token)
        await self.limits.reserve(principal, amount)
        context = AuthzRequest(subject=principal.subject, tenant=principal.tenant,
                               resource_tenant=resource_tenant or principal.tenant,
                               roles=principal.roles, model=model, action=action, within_quota=True)
        decision = await self.policy.decide(context)
        decision_id = uuid.uuid4().hex
        audit.info(json.dumps({"event": "authorization", "decision_id": decision_id,
                               "policy_version": decision.policy_version,
                               "reason": decision.reason, "subject": principal.subject,
                               "tenant": principal.tenant, "action": action,
                               "model": model if model in {m.id for m in self.profile.models} else "unknown"}))
        if not decision.allow:
            raise Denied("AUTHORIZATION_DENIED", 403)
        return principal, decision_id

    async def chat(self, token: str, data: dict, resource_tenant: str | None = None):
        try:
            request = Chat.model_validate(data)
        except ValidationError:
            raise Denied("REQUEST_INVALID", 400) from None
        model = next((m for m in self.profile.models if m.id == request.model), None)
        if model is not None and request.max_tokens > model.max_tokens:
            raise Denied("MODEL_TOKEN_LIMIT", 400)
        principal, decision_id = await self.authorize(token, "chat", request.model, resource_tenant,
                                                     request.max_tokens + sum(len(m.content) for m in request.messages))
        # Reconstruct the forwarded body; no caller metadata, URLs, tools or identity survive.
        body = {"model": request.model, "messages": [m.model_dump() for m in request.messages],
                "max_tokens": request.max_tokens, "temperature": 0, "stream": False,
                "metadata": {"p006_subject": principal.subject, "p006_tenant": principal.tenant,
                             "decision_id": decision_id, "policy_version": "p006-authz-v1"}}
        async with asyncio.timeout(12):
            async with self.concurrent:
                credentials = await self.vault.read()
                result = await self.gateway.complete(body, credentials)
        # Project a tiny response shape. Never forward arbitrary provider errors/metadata.
        try:
            content = result["choices"][0]["message"]["content"]
            if not isinstance(content, str) or not content.startswith("P006 synthetic response ") or len(content) > 256:
                raise ValueError()
            if any(s in content for s in (credentials["gateway_key"], credentials["provider_key"])):
                raise ValueError()
        except (KeyError, IndexError, TypeError, ValueError):
            raise Denied("RESPONSE_INVALID", 502) from None
        return {"id": decision_id, "object": "chat.completion", "created": int(time.time()),
                "model": request.model, "choices": [{"index": 0, "message": {"role": "assistant",
                            "content": content}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


def create_app(engine: Engine) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def bounds(request: Request, call_next):
        correlation = uuid.uuid4().hex
        try:
            if request.headers.get("origin") not in {None, "http://127.0.0.1:8086"}:
                raise Denied("ORIGIN_DENIED", 403)
            if any(k.lower() in {"x-tenant-id", "x-user-id", "x-user-role", "x-p006-subject",
                                 "x-user", "x-tenant", "x-role", "x-email"}
                   or k.lower().startswith("x-openwebui-user-") for k in request.headers):
                raise Denied("IDENTITY_HEADER_DENIED", 400)
            length = request.headers.get("content-length")
            if length and (not length.isdigit() or int(length) > engine.profile.max_request_bytes):
                raise Denied("REQUEST_SIZE", 413)
            size = 0
            chunks = []
            async for chunk in request.stream():
                size += len(chunk)
                if size > engine.profile.max_request_bytes:
                    raise Denied("REQUEST_SIZE", 413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
            async with asyncio.timeout(16):
                response = await call_next(request)
            response.headers["X-Request-ID"] = correlation
            response.headers["Cache-Control"] = "no-store"
            return response
        except Denied as error:
            return JSONResponse({"error": error.code, "request_id": correlation}, status_code=error.status)
        except Exception:
            # Exception text and request data intentionally excluded from logs/response.
            audit.info(json.dumps({"event": "request_failed", "request_id": correlation}))
            return JSONResponse({"error": "REQUEST_FAILED", "request_id": correlation}, status_code=503)

    def bearer(request: Request) -> str:
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer ") or len(header) < 10:
            raise Denied("AUTHENTICATION_REQUIRED", 401)
        return header[7:]

    @app.get("/healthz")
    async def health():
        return {"status": "alive", "profile": "hardened"}

    @app.get("/readyz")
    async def ready():
        await engine.vault.read()
        await engine.identity.http.request("GET", engine.profile.identity.jwks_url)
        # Empty input must produce the real, versioned default-deny decision.
        result = await engine.policy.http.request("POST", "http://opa:8181/v1/data/p006/authz/decision",
                                                  json={"input": {}})
        if result.get("result") != {"allow": False, "reason": "DEFAULT_DENY", "policy_version": "p006-authz-v1"}:
            raise Denied("POLICY_INVALID")
        alive = await engine.gateway.http.request("GET", "http://litellm:4000/health/liveliness", allow_string=True)
        if alive != "I'm alive!":
            raise Denied("GATEWAY_NOT_READY")
        return {"status": "ready", "profile": "hardened"}

    @app.get("/v1/models")
    async def models(request: Request):
        principal, _ = await engine.authorize(bearer(request), "models", "local-basic", None)
        return {"object": "list", "data": [{"id": m.id, "object": "model", "owned_by": "p006"}
                                           for m in engine.profile.models if m.required_role in principal.roles]}

    @app.post("/v1/chat/completions")
    @app.post("/tenants/{tenant}/v1/chat/completions")
    async def chat(request: Request, tenant: str | None = None):
        token = bearer(request)
        try:
            data = await request.json()
        except ValueError:
            raise Denied("JSON_INVALID", 400) from None
        result = await engine.chat(token, data, tenant)
        if data.get("stream"):
            content = result["choices"][0]["message"]["content"]
            chunk = {"id": result["id"], "object": "chat.completion.chunk", "created": result["created"],
                     "model": result["model"], "choices": [{"index": 0, "delta": {"role": "assistant",
                     "content": content}, "finish_reason": None}]}
            return StreamingResponse(iter([f"data: {json.dumps(chunk)}\n\n", "data: [DONE]\n\n"]),
                                     media_type="text/event-stream")
        return result

    @app.post("/admin/{action}")
    async def admin(action: str, request: Request):
        if action not in {"tenant-admin", "platform-admin"}:
            raise Denied("ACTION_DENIED", 403)
        await engine.authorize(bearer(request), cast(Action, action), "local-basic", None)
        return {"status": "authorized-synthetic-operation"}

    @app.exception_handler(Denied)
    async def denied_handler(request, error):
        return JSONResponse({"error": error.code}, status_code=error.status)

    return app
