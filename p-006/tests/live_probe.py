"""Real local-service probes. Output contains statuses; credentials stay in memory."""

import base64
import hashlib
import html
import json
import re
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

RESULTS = []
HTTP = httpx.Client(timeout=20, trust_env=False, follow_redirects=False)
OPERATOR = Path("/run/operator")
USERS = json.loads((OPERATOR / "users.json").read_text())
CLIENTS = json.loads((OPERATOR / "clients.json").read_text())
CHAT = {"model": "local-basic", "messages": [{"role": "user", "content": "Synthetic"}], "max_tokens": 8}
TOKENS = {}
REFRESH = {}


def record(test_id, condition, observation):
    RESULTS.append({"test_id": test_id, "status": "PASS" if condition else "FAIL", "observation": observation})


def local(url):
    for origin, internal in [("http://127.0.0.1:8086", "http://webui:8080"),
                             ("http://127.0.0.1:8087", "http://keycloak:8080")]:
        if url == origin or url.startswith(origin + "/"):
            return internal + url[len(origin):]
    if url.startswith("http://keycloak:8080/") or url.startswith("http://webui:8080/"):
        return url
    raise ValueError("unapproved redirect")


def login_form(client, response, username):
    match = re.search(r'<form[^>]+action="([^"]+)"', response.text)
    if not match:
        raise ValueError("login form missing")
    return client.post(local(html.unescape(match[1])), data={"username": username, "password": USERS[username],
                                                           "credentialId": ""})


def token(username):
    if username in TOKENS:
        return TOKENS[username]
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    with httpx.Client(timeout=20, trust_env=False, follow_redirects=False) as client:
        response = client.get("http://keycloak:8080/realms/p006/protocol/openid-connect/auth", params={
            "client_id": "open-webui", "redirect_uri": "http://127.0.0.1:8086/oauth/oidc/callback",
            "response_type": "code", "scope": "openid email profile", "state": secrets.token_hex(16),
            "code_challenge": challenge, "code_challenge_method": "S256"})
        response = login_form(client, response, username)
        code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
        response = client.post("http://keycloak:8080/realms/p006/protocol/openid-connect/token", data={
            "grant_type": "authorization_code", "client_id": "open-webui", "client_secret": CLIENTS["oauth"],
            "redirect_uri": "http://127.0.0.1:8086/oauth/oidc/callback", "code": code, "code_verifier": verifier})
        value = response.json()["access_token"]
        REFRESH[username] = response.json()["refresh_token"]
        TOKENS[username] = value
        return value


def pep(username="ada", body=None, path="/v1/chat/completions", headers=None):
    return HTTP.post("http://pep:8080" + path, json=body or CHAT,
                     headers={"Authorization": "Bearer " + token(username), **(headers or {})})


def vault_token(path, role):
    response = HTTP.post("http://vault:8200/v1/auth/approle/login", json=json.loads(Path(path).read_text()))
    data = response.json()["auth"]
    record("V01-" + role, data["policies"] == [role] and data["lease_duration"] <= 60,
           "Real Vault AppRole has only its named policy and a bounded lease")
    return {"X-Vault-Token": data["client_token"]}


def check_core():
    record("A01", HTTP.post("http://pep:8080/v1/chat/completions", json=CHAT).status_code == 401,
           "Protected PEP rejects unauthenticated request")
    result = pep()
    record("A02-P02-L01", result.status_code == 200 and "P006 synthetic response " in result.text,
           "Real Keycloak Code+PKCE token traverses PEP, OPA, Vault, LiteLLM and deterministic backend")
    record("P03", pep(body={**CHAT, "model": "local-admin"}).status_code == 403,
           "Ordinary user denied privileged model by real OPA on PEP path")
    record("P04", pep(path="/tenants/tenant-b/v1/chat/completions").status_code == 403,
           "Tenant A token denied Tenant B resource")
    record("P05", pep(path="/admin/tenant-admin").status_code == 403, "Normal user denied tenant admin action")
    record("P06", pep("admin-a", path="/admin/platform-admin").status_code == 403,
           "Tenant administrator denied platform operation")
    record("P02-admin", pep("admin-a", path="/admin/tenant-admin").status_code == 200,
           "Tenant administrator allowed own synthetic administrative operation")
    record("P02-platform", pep("platform-admin", path="/admin/platform-admin").status_code == 200,
           "Platform administrator allowed explicit synthetic platform operation")
    record("L02", pep(body={**CHAT, "model": "unlisted-model"}).status_code == 403, "Unknown model denied")
    record("L04", pep(body={**CHAT, "api_base": "https://example.invalid"}).status_code == 400,
           "Arbitrary provider URL rejected by strict PEP contract")
    record("A09", pep(headers={"X-User-ID": "platform-admin"}).status_code == 400, "Forged user header rejected")
    record("A10", pep(headers={"X-Tenant-ID": "tenant-b"}).status_code == 400, "Forged tenant header rejected")
    invalid = token("ada").split(".")
    invalid[2] = ("a" if invalid[2][0] != "a" else "b") + invalid[2][1:]
    response = HTTP.post("http://pep:8080/v1/chat/completions", json=CHAT,
                         headers={"Authorization": "Bearer " + ".".join(invalid)})
    record("A03", response.status_code == 401, "Corrupted Keycloak token signature rejected")
    record("U06", pep(headers={"Origin": "https://example.invalid"}).status_code == 403, "Unapproved origin rejected")
    record("U07", pep(body={**CHAT, "messages": [{"role": "user", "content": "x" * 20000}]}).status_code == 413,
           "Oversized payload rejected before authorization")
    record("P09", HTTP.post("http://litellm:4000/v1/chat/completions", json=CHAT,
                             headers={"Authorization": "Bearer invalid-synthetic-key"}).status_code == 403,
           "Real LiteLLM rejects gateway request without PEP proof")
    record("L-admin", HTTP.get("http://litellm:4000/key/list").status_code in {401, 403},
           "Gateway administration rejects unauthenticated operator")
    record("L-backend", HTTP.post("http://model:8000/v1/chat/completions", json=CHAT).status_code == 403,
           "Deterministic backend requires its own synthetic workload credential")
    marker = "P006_" + "DUMMY_SECRET_" + secrets.token_hex(16)
    response = pep("ari", body={**CHAT, "messages": [{"role": "user", "content": marker}]})
    record("V07-U05", response.status_code == 200 and marker not in response.text,
           "Synthetic secret marker in prompt absent from projected browser/API response")


def check_vault():
    headers = vault_token("/run/operator/approle.json", "p006-rotator")
    current = HTTP.get("http://vault:8200/v1/p006/data/gateway", headers=headers)
    record("V02", current.status_code == 200, "Narrow Vault identity reads its designated KV-v2 path")
    value = current.json()["data"]
    # Only the trusted operator can create this synthetic PEP proof for tamper/replay checks.
    from p006.adapters import seal
    body = {**CHAT, "temperature": 0, "stream": False, "metadata": {
        "p006_subject": "00000000-0000-4000-8000-000000000001", "p006_tenant": "tenant-a",
        "decision_id": secrets.token_hex(16), "policy_version": "p006-authz-v1"}}
    stamp, nonce = str(int(time.time())), secrets.token_hex(16)
    proof_headers = {"Authorization": "Bearer " + value["data"]["gateway_key"], "X-P006-Time": stamp,
                     "X-P006-Nonce": nonce, "X-P006-Proof": seal(value["data"]["gateway_key"], body, nonce, stamp)}
    gateway = "http://litellm:4000/v1/chat/completions"
    record("P10-proof", HTTP.post(gateway, json=body, headers=proof_headers).status_code == 200,
           "Real LiteLLM accepts a correctly bound fresh proof from the trusted test operator")
    record("P10-replay", HTTP.post(gateway, json=body, headers=proof_headers).status_code == 403,
           "Real LiteLLM rejects reuse of an already consumed proof nonce")
    record("L08", HTTP.post(gateway, json={**body, "model": "local-admin"}, headers=proof_headers).status_code == 403,
           "Authorized proof cannot be reused for a changed model/body")
    record("V02-scope", HTTP.get("http://vault:8200/v1/p006/data/unrelated", headers=headers).status_code == 403,
           "Read outside intended path denied by real Vault ACL")
    stranger = vault_token("/run/unrelated/approle.json", "p006-unrelated")
    record("V03", HTTP.get("http://vault:8200/v1/p006/data/gateway", headers=stranger).status_code == 403,
           "Unrelated Vault identity denied credentials")
    HTTP.post("http://vault:8200/v1/auth/token/revoke-self", headers=stranger)
    record("V04", HTTP.get("http://vault:8200/v1/p006/data/gateway", headers=stranger).status_code == 403,
           "Revoked real Vault token denied")
    rotated = {**value["data"], "gateway_key": secrets.token_urlsafe(48)}
    updated = HTTP.post("http://vault:8200/v1/p006/data/gateway", headers=headers,
                        json={"data": rotated, "options": {"cas": value["metadata"]["version"]}})
    result = pep("bea")
    record("V06", updated.status_code == 200 and updated.json()["data"]["version"] > value["metadata"]["version"]
           and result.status_code == 200, "Gateway rotation increments KV version and is used without fallback/cache")
    HTTP.post("http://vault:8200/v1/auth/token/revoke-self", headers=headers)


def check_ui():
    with httpx.Client(timeout=30, trust_env=False, follow_redirects=False) as browser:
        record("U01-unauth", browser.get("http://webui:8080/api/v1/auths/").status_code == 401,
               "Actual Open WebUI protected user API rejects unauthenticated client")
        response = browser.get("http://webui:8080/oauth/oidc/login")
        response = browser.get(local(response.headers["location"]))
        response = login_form(browser, response, "ben")
        response = browser.get(local(response.headers["location"]))
        record("U01", response.status_code in {302, 303, 307} and bool(browser.cookies),
               "Actual Open WebUI OAuth callback completes Keycloak Authorization Code flow")
        response = browser.get("http://webui:8080/api/v1/auths/")
        record("U03-role", response.status_code == 200 and response.json().get("role") == "user",
               "First ordinary OAuth login retains normal user role")
        models = browser.get("http://webui:8080/api/models")
        record("U-model-list", models.status_code == 200 and
               [m["id"] for m in models.json().get("data", [])] == ["local-basic"],
               "Native Open WebUI access grants expose only the allowed ordinary-user model")
        response = browser.post("http://webui:8080/api/chat/completions", json={**CHAT, "stream": False})
        record("U02", response.status_code == 200 and "P006 synthetic response " in response.text,
               "Actual Open WebUI chat path forwards Keycloak access token through system_oauth to PEP chain")
        record("U03", browser.get("http://webui:8080/api/v1/users/").status_code in {401, 403},
               "Ordinary Open WebUI user denied administrative user API")
        response = browser.post("http://webui:8080/api/v1/functions/create", json={"id": "synthetic", "name": "synthetic",
                               "content": "synthetic inert content", "meta": {}})
        record("U04", response.status_code in {401, 403}, "Ordinary user cannot create executable function")
        record("U08", browser.post("http://webui:8080/api/chat/completions", json={**CHAT, "model": "local-admin"}).status_code in {400, 403, 404},
               "Direct Open WebUI API cannot select privileged model as normal user")
        record("U-cookie", all(c.has_nonstandard_attr("HttpOnly") for c in browser.cookies.jar if c.name in {"token", "session"}),
               "Observed application session cookies are HttpOnly; loopback HTTP has no Secure flag")


def check_lifecycle():
    response = HTTP.post("http://keycloak:8080/realms/p006/protocol/openid-connect/token", data={
        "grant_type": "client_credentials", "client_id": "p006-operator", "client_secret": CLIENTS["operator"],
        "scope": "kc-admin-api"})
    admin = {"Authorization": "Bearer " + response.json()["access_token"]}
    user = "http://keycloak:8080/admin/realms/p006/users/00000000-0000-4000-8000-000000000001"
    disabled = HTTP.put(user, headers=admin, json={"enabled": False})
    try:
        record("A12", disabled.status_code == 204 and pep().status_code == 401,
               "Real Keycloak deactivation is enforced by introspection on previously issued token")
    finally:
        HTTP.put(user, headers=admin, json={"enabled": True})
    token("ari")
    response = HTTP.post("http://keycloak:8080/realms/p006/protocol/openid-connect/logout", data={
        "client_id": "open-webui", "client_secret": CLIENTS["oauth"], "refresh_token": REFRESH["ari"]})
    record("A11", response.status_code == 204 and pep("ari").status_code == 401,
           "Keycloak logout invalidates existing session token on PEP path")


def provision_ui():
    """Use the real platform-admin OAuth session and supported model/access-grant API."""
    with httpx.Client(timeout=30, trust_env=False, follow_redirects=False) as browser:
        response = browser.get("http://webui:8080/oauth/oidc/login")
        response = browser.get(local(response.headers["location"]))
        response = login_form(browser, response, "platform-admin")
        response = browser.get(local(response.headers["location"]))
        account = browser.get("http://webui:8080/api/v1/auths/")
        if account.status_code != 200 or account.json().get("role") != "admin":
            raise RuntimeError("platform OAuth provisioning unavailable")
        for model in ["local-basic", "local-admin"]:
            grants = [{"principal_type": "user", "principal_id": "*", "permission": "read"}] if model == "local-basic" else []
            response = browser.post("http://webui:8080/api/v1/models/create", json={
                "id": model, "name": model, "base_model_id": None, "meta": {},
                "params": {}, "access_grants": grants, "is_active": True})
            if response.status_code != 200:
                raise RuntimeError("native model provisioning denied")
        browser.post("http://webui:8080/api/v1/auths/signout")
        record("UI-provision", True, "Real platform-admin OAuth provisioned two fixed native models and least-privilege UI read grants")


def wait_ready():
    end = time.monotonic() + 180
    while time.monotonic() < end:
        try:
            if HTTP.get("http://pep:8080/readyz").status_code == 200 and HTTP.get("http://webui:8080/health").status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise RuntimeError("readiness timed out")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode == "provision":
        wait_ready()
        provision_ui()
    elif mode == "recovery":
        response = pep("ari")
        record("fault-recovery", response.status_code == 200 and "P006 synthetic response " in response.text,
               "Restored dependency permits a fresh fully authorized request")
    elif mode == "probe":
        record("fault-probe", pep("ari").status_code == 503, "Dependency disconnect produces safe PEP 503")
    else:
        wait_ready()
        check_core()
        check_vault()
        check_ui()
        check_lifecycle()
    print(json.dumps({"results": RESULTS}))
    raise SystemExit(1 if any(r["status"] == "FAIL" for r in RESULTS) else 0)


if __name__ == "__main__":
    try:
        main()
    except (httpx.HTTPError, ValueError, KeyError, RuntimeError, AttributeError) as error:
        RESULTS.append({"test_id": "execution", "status": "BLOCKED", "observation": type(error).__name__})
        print(json.dumps({"results": RESULTS}))
        raise SystemExit(2) from None
