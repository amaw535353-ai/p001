import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from p006.adapters import Gateway, Policy, Vault
from p006.identity import Identity
from p006.models import Profile
from p006.pep import Engine, create_app
from p006.transport import Transport

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


@pytest.fixture
def profile():
    return Profile.model_validate_json((ROOT / "config/hardened.json").read_text())


@pytest.fixture(scope="session")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def lab(profile, key):
    """Explicit adapter fixtures: no claim to run Keycloak/OPA/Vault/LiteLLM here."""
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="fixture-key", use="sig", alg="RS256")
    state = SimpleNamespace(calls=[], active=True, policy=None, vault_mode="ok", gateway_mode="ok",
                            policy_mode="ok", version=1, credential="fixture-only-" + "a" * 40,
                            provider="fixture-only-" + "b" * 40, jwk=jwk, introspected=0)
    principal = profile.principals[0]

    def token(**updates):
        now = int(time.time())
        claims = dict(sub=principal.subject, iss=profile.identity.issuer, aud="p006-pep", exp=now + 120,
                      nbf=now - 1, iat=now - 1, jti="fixture-jti", sid="fixture-session", tenant=principal.tenant,
                      p006_roles=principal.roles, azp="open-webui")
        claims.update(updates)
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "fixture-key"})

    def route(request):
        state.calls.append((request.url.host, request.url.path, request.content))
        host, path = request.url.host, request.url.path
        if host == "keycloak":
            if path.endswith("/certs"):
                return httpx.Response(200, json={"keys": [state.jwk]})
            state.introspected += 1
            return httpx.Response(200, json={"active": state.active, "sub": state.subject})
        if host == "opa":
            if state.policy_mode == "outage":
                raise httpx.ConnectError("fixture outage")
            if state.policy_mode == "bad":
                return httpx.Response(200, json={"result": {"allow": True}})
            if state.policy_mode == "version":
                return httpx.Response(200, json={"result": {"allow": True, "reason": "ALLOW", "policy_version": "v999"}})
            context = json.loads(request.content)["input"]
            state.context = context
            # This is an adapter fixture. Real Rego is evaluated separately by OPA.
            allowed = context.get("model") == "local-basic" and context.get("action") in {"chat", "models"}
            allowed = allowed and context.get("tenant") == context.get("resource_tenant")
            if state.policy is not None:
                allowed = state.policy
            return httpx.Response(200, json={"result": {"allow": allowed, "reason": "ALLOW" if allowed else "DEFAULT_DENY",
                                                        "policy_version": "p006-authz-v1"}})
        if host == "vault":
            if state.vault_mode == "outage":
                raise httpx.ConnectError("fixture outage")
            if path.endswith("/login"):
                policies = ["root"] if state.vault_mode == "root" else ["p006-pep"]
                return httpx.Response(200, json={"auth": {"client_token": "fixture-token", "policies": policies,
                                                        "lease_duration": 60}})
            if path.endswith("revoke-self"):
                return httpx.Response(200, json={})
            if state.vault_mode == "revoked":
                return httpx.Response(403, json={"errors": [state.credential]})
            return httpx.Response(200, json={"data": {"data": {"gateway_key": state.credential,
                                           "provider_key": state.provider}, "metadata": {"version": state.version}}})
        if host == "litellm":
            if request.method == "GET":
                return httpx.Response(200, json="I'm alive!")
            state.forwarded = json.loads(request.content)
            state.headers = request.headers
            if state.gateway_mode == "outage":
                raise httpx.ReadTimeout(state.credential)
            if state.gateway_mode == "huge":
                return httpx.Response(200, content=b"x" * 70000)
            content = "P006 synthetic response 01234567"
            if state.gateway_mode == "leak":
                content += state.credential
            if state.gateway_mode == "bad":
                return httpx.Response(200, json={"error": state.credential})
            return httpx.Response(200, json={"choices": [{"message": {"content": content}}],
                                            "internal_secret": state.credential})
        raise AssertionError("unapproved adapter destination")

    state.subject = principal.subject
    transport = Transport(httpx.AsyncClient(transport=httpx.MockTransport(route), timeout=1))
    identity = Identity(profile, transport, "fixture-introspection-secret")
    engine = Engine(profile, identity, Policy(transport), Vault(transport, {"role_id": "fixture", "secret_id": "fixture"}),
                    Gateway(transport))
    state.token, state.engine, state.identity, state.http = token, engine, identity, transport
    state.app = create_app(engine)
    state.chat = {"model": "local-basic", "messages": [{"role": "user", "content": "Synthetic request"}]}
    return state


@pytest.fixture
async def client(lab):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=lab.app), base_url="http://test") as client:
        yield client
    await lab.http.client.aclose()
