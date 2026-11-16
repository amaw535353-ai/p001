#!/usr/bin/env python3
"""Ephemeral Vault bootstrap. Root/unseal material stays only in process memory."""

import json
import secrets
import time
from pathlib import Path

import httpx


def main():
    base = Path("/bootstrap")
    with httpx.Client(base_url="http://vault:8200/v1", trust_env=False, timeout=5) as client:
        for _ in range(60):
            try:
                response = client.get("/sys/init")
                if response.status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(1)
        else:
            raise RuntimeError("VAULT_BOOTSTRAP_NOT_READY")
        if response.json()["initialized"]:
            raise RuntimeError("VAULT_ALREADY_INITIALIZED_REFUSED")
        response = client.put("/sys/init", json={"secret_shares": 1, "secret_threshold": 1})
        response.raise_for_status()
        init = response.json()
        client.put("/sys/unseal", json={"key": init["keys"][0]}).raise_for_status()
        client.headers["X-Vault-Token"] = init["root_token"]
        del init

        def send(method, path, data):
            r = client.request(method, path, json=data)
            if r.status_code >= 300:
                raise RuntimeError("VAULT_BOOTSTRAP_DENIED_" + str(r.status_code) + "_" + path)
            return r.json() if r.content else {}

        send("POST", "/sys/mounts/p006", {"type": "kv", "options": {"version": "2"}})
        send("POST", "/sys/auth/approle", {"type": "approle"})
        key = secrets.token_urlsafe(48)
        provider = (base / "model/provider-key").read_text()
        send("POST", "/p006/data/gateway", {"data": {"gateway_key": key, "provider_key": provider}})
        roles = {}
        for role, directory, capabilities in [
            ("p006-pep", "pep", ["read"]), ("p006-gateway", "gateway", ["read"]),
            ("p006-rotator", "operator", ["read", "create", "update"]),
            ("p006-unrelated", "unrelated", [])
        ]:
            policy = 'path "auth/token/revoke-self" { capabilities = ["update"] }\n'
            if capabilities:
                policy += 'path "p006/data/gateway" { capabilities = ' + json.dumps(capabilities) + ' }\n'
            send("PUT", f"/sys/policies/acl/{role}", {"policy": policy})
            send("POST", f"/auth/approle/role/{role}", {"token_policies": [role], "token_no_default_policy": True,
                 "token_ttl": "60s", "token_max_ttl": "60s", "secret_id_ttl": "1h", "secret_id_num_uses": 0})
            role_id = send("GET", f"/auth/approle/role/{role}/role-id", None)["data"]["role_id"]
            secret_id = send("POST", f"/auth/approle/role/{role}/secret-id", {})["data"]["secret_id"]
            roles[directory] = {"role_id": role_id, "secret_id": secret_id}
        # No retained root credential or unseal key, even in ignored operator files.
        send("POST", "/auth/token/revoke-self", {})
    # Private IPC to the operator, captured in memory; bootstrap has Docker logging disabled.
    print(json.dumps({"roles": roles}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        code = str(error) if type(error) is RuntimeError and str(error).startswith("VAULT_") else type(error).__name__
        raise SystemExit("BLOCKED: Vault bootstrap failed: " + code) from None
