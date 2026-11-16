"""Real PDP, Vault and LiteLLM adapters; no permissive dependency fallback."""

import hashlib
import hmac
import json
import time
import uuid

from pydantic import ValidationError

from p006.models import AuthzDecision, AuthzRequest
from p006.transport import Denied, Transport


class Policy:
    def __init__(self, http: Transport):
        self.http = http

    async def decide(self, request: AuthzRequest) -> AuthzDecision:
        result = await self.http.request("POST", "http://opa:8181/v1/data/p006/authz/decision",
                                         json={"input": request.model_dump()})
        try:
            return AuthzDecision.model_validate(result["result"])
        except (KeyError, ValidationError):
            raise Denied("POLICY_INVALID") from None


class Vault:
    def __init__(self, http: Transport, approle: dict, role: str = "p006-pep"):
        self.http = http
        self.approle = approle
        self.role = role

    async def read(self) -> dict:
        token = None
        try:
            login = await self.http.request("POST", "http://vault:8200/v1/auth/approle/login",
                                            json=self.approle)
            auth = login["auth"]
            if set(auth["policies"]) != {self.role} or not 1 <= auth["lease_duration"] <= 300:
                raise ValueError()
            token = auth["client_token"]
            result = await self.http.request("GET", "http://vault:8200/v1/p006/data/gateway",
                                             headers={"X-Vault-Token": token})
            data = result["data"]["data"]
            if set(data) != {"gateway_key", "provider_key"}:
                raise ValueError()
            if any(not isinstance(v, str) or len(v) < 32 for v in data.values()):
                raise ValueError()
            return {**data, "version": result["data"]["metadata"]["version"]}
        except Denied:
            raise
        except (KeyError, TypeError, ValueError):
            raise Denied("SECRET_INVALID") from None
        finally:
            if token:
                # Revoke each short-lived token. Failure never changes a denied request to allow.
                try:
                    await self.http.request("POST", "http://vault:8200/v1/auth/token/revoke-self",
                                            headers={"X-Vault-Token": token})
                except Denied:
                    pass


def seal(key: str, body: dict, nonce: str, stamp: str) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hmac.new(key.encode(), f"{stamp}\n{nonce}\n{canonical}".encode(), hashlib.sha256).hexdigest()


class Gateway:
    def __init__(self, http: Transport):
        self.http = http

    async def complete(self, body: dict, credential: dict) -> dict:
        nonce, stamp = uuid.uuid4().hex, str(int(time.time()))
        return await self.http.request("POST", "http://litellm:4000/v1/chat/completions",
                                      json=body, headers={
                                          "Authorization": f"Bearer {credential['gateway_key']}",
                                          "X-P006-Nonce": nonce, "X-P006-Time": stamp,
                                          "X-P006-Proof": seal(credential["gateway_key"], body, nonce, stamp)})
