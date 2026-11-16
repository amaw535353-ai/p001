import json

import pytest

from p006.adapters import seal
from p006.transport import Denied


async def test_p01_policy_deny_never_reaches_vault(lab):
    lab.policy = False
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), lab.chat)
    assert all(host not in {"vault", "litellm"} for host, _, _ in lab.calls)


async def test_p02_policy_allow_uses_trusted_context(lab):
    await lab.engine.chat(lab.token(), lab.chat)
    assert lab.context["subject"] == lab.subject
    assert lab.context["resource_tenant"] == "tenant-a"


async def test_p03_policy_unauthorized_model(lab):
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), {**lab.chat, "model": "local-admin"})
    assert all(host != "litellm" for host, _, _ in lab.calls)


async def test_p04_policy_cross_tenant(lab):
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), lab.chat, "tenant-b")


async def test_p05_policy_normal_user_admin_denied(client, lab):
    r = await client.post("/admin/tenant-admin", headers={"Authorization": "Bearer " + lab.token()})
    assert r.status_code == 403


async def test_p06_policy_tenant_admin_not_platform(lab):
    principal = lab.engine.profile.principals[2]
    lab.subject = principal.subject
    with pytest.raises(Denied):
        await lab.engine.authorize(lab.token(sub=principal.subject, p006_roles=principal.roles),
                                    "platform-admin", "local-basic", None)


async def test_p07_policy_outage_fails_closed(lab):
    lab.policy_mode = "outage"
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), lab.chat)
    assert not any(h in {"vault", "litellm"} for h, _, _ in lab.calls)


async def test_p08_policy_invalid_response_fails_closed(lab):
    lab.policy_mode = "bad"
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), lab.chat)


async def test_policy_unknown_version(lab):
    lab.policy_mode = "version"
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), lab.chat)


async def test_p10_policy_authorized_request_reconstructed(lab):
    await lab.engine.chat(lab.token(), lab.chat)
    assert lab.forwarded["model"] == lab.context["model"]
    assert lab.forwarded["metadata"]["p006_tenant"] == lab.context["tenant"]
    assert lab.forwarded["metadata"]["p006_subject"] == lab.context["subject"]
    assert "X-P006-Proof" in lab.headers


async def test_v01_vault_root_policy_rejected(lab):
    lab.vault_mode = "root"
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), lab.chat)
    assert not any(h == "litellm" for h, _, _ in lab.calls)


async def test_v02_vault_reads_and_revokes_per_request(lab):
    await lab.engine.chat(lab.token(), lab.chat)
    paths = [p for h, p, _ in lab.calls if h == "vault"]
    assert paths == ["/v1/auth/approle/login", "/v1/p006/data/gateway", "/v1/auth/token/revoke-self"]


async def test_v04_vault_revoked_token_denied(lab):
    lab.vault_mode = "revoked"
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), lab.chat)


async def test_v05_vault_outage_no_fallback(lab):
    lab.vault_mode = "outage"
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), lab.chat)
    assert not any(h == "litellm" for h, _, _ in lab.calls)


async def test_v06_vault_rotation_used_without_cache(lab):
    await lab.engine.chat(lab.token(), lab.chat)
    old = lab.headers["Authorization"]
    lab.credential = "fixture-rotated-" + "c" * 40
    lab.version += 1
    await lab.engine.chat(lab.token(), lab.chat)
    assert lab.headers["Authorization"] != old
    assert lab.headers["Authorization"] == "Bearer " + lab.credential


async def test_v07_vault_secret_not_returned_or_logged(lab, caplog):
    caplog.set_level("INFO", logger="p006.audit")
    result = await lab.engine.chat(lab.token(), lab.chat)
    combined = json.dumps(result) + caplog.text
    assert lab.credential not in combined and lab.provider not in combined
    assert "Synthetic request" not in caplog.text
    assert "decision_id" in caplog.text


async def test_l01_gateway_local_request_and_safe_projection(lab):
    result = await lab.engine.chat(lab.token(), lab.chat)
    assert result["choices"][0]["message"]["content"].startswith("P006 synthetic response ")
    assert "internal_secret" not in result


async def test_l02_gateway_unknown_model(lab):
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), {**lab.chat, "model": "unknown"})


async def test_l03_gateway_provider_route_override(lab):
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), {**lab.chat, "provider": "external"})
    assert not lab.calls


async def test_l04_gateway_arbitrary_url_rejected(lab):
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), {**lab.chat, "api_base": "http://attacker.invalid"})


async def test_l05_gateway_key_not_in_http_error(client, lab):
    lab.gateway_mode = "outage"
    r = await client.post("/v1/chat/completions", json=lab.chat, headers={"Authorization": "Bearer " + lab.token()})
    assert r.status_code == 503 and lab.credential not in r.text


async def test_l06_gateway_rate_limit(lab):
    lab.engine.limits.rate = 1
    await lab.engine.chat(lab.token(), lab.chat)
    with pytest.raises(Denied) as error:
        await lab.engine.chat(lab.token(), lab.chat)
    assert error.value.status == 429


async def test_gateway_tenant_token_budget(lab):
    lab.engine.limits.tokens = 128
    with pytest.raises(Denied) as error:
        await lab.engine.chat(lab.token(), {**lab.chat, "messages": [{"role": "user", "content": "x" * 1000}]})
    assert error.value.status == 429


async def test_gateway_model_specific_token_ceiling(lab):
    with pytest.raises(Denied) as error:
        await lab.engine.chat(lab.token(), {**lab.chat, "max_tokens": 65})
    assert error.value.status == 400
    assert not lab.calls


async def test_gateway_concurrent_requests_remain_bounded(lab, monkeypatch):
    import asyncio
    active = 0
    peak = 0
    async def slow_gateway(body, credential):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return {"choices": [{"message": {"content": "P006 synthetic response bounded"}}]}
    monkeypatch.setattr(lab.engine.gateway, "complete", slow_gateway)
    results = await asyncio.gather(*(lab.engine.chat(lab.token(), lab.chat) for _ in range(8)))
    assert len(results) == 8 and peak == 4


async def test_l07_gateway_timeout_safely_denied(lab):
    lab.gateway_mode = "outage"
    with pytest.raises(Denied) as error:
        await lab.engine.chat(lab.token(), lab.chat)
    assert lab.credential not in error.value.code


async def test_l08_gateway_identity_metadata_override(lab):
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), {**lab.chat, "metadata": {"p006_subject": "other"}})


async def test_gateway_proof_binds_whole_body():
    key = "fixture-proof-only"
    original = {"model": "local-basic", "metadata": {"p006_tenant": "tenant-a"}}
    changed = {**original, "model": "local-admin"}
    assert seal(key, original, "nonce", "stamp") != seal(key, changed, "nonce", "stamp")
    assert seal(key, original, "nonce", "stamp") != seal(key, original, "nonce-two", "stamp")


async def test_gateway_oversized_response_denied(lab):
    lab.gateway_mode = "huge"
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), lab.chat)


async def test_gateway_leaking_provider_response_denied(lab):
    lab.gateway_mode = "leak"
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), lab.chat)


async def test_gateway_malformed_provider_response_denied(lab):
    lab.gateway_mode = "bad"
    with pytest.raises(Denied):
        await lab.engine.chat(lab.token(), lab.chat)


async def test_u06_unapproved_origin(client, lab):
    r = await client.post("/v1/chat/completions", json=lab.chat, headers={"Origin": "https://attacker.invalid"})
    assert r.status_code == 403 and not lab.calls


async def test_u07_input_size_bounded(client, lab):
    r = await client.post("/v1/chat/completions", content=b"x" * 20000)
    assert r.status_code == 413 and not lab.calls


async def test_u08_direct_api_still_authorized(client, lab):
    r = await client.post("/tenants/tenant-b/v1/chat/completions", json=lab.chat,
                          headers={"Authorization": "Bearer " + lab.token()})
    assert r.status_code == 403


async def test_api_health_no_config_or_credentials(client):
    r = await client.get("/healthz")
    assert r.json() == {"status": "alive", "profile": "hardened"}


async def test_api_readiness_validates_native_litellm_scalar_health(client):
    response = await client.get("/readyz")
    assert response.status_code == 200


async def test_api_model_list_matches_role(client, lab):
    r = await client.get("/v1/models", headers={"Authorization": "Bearer " + lab.token()})
    assert [m["id"] for m in r.json()["data"]] == ["local-basic"]


async def test_api_stream_is_bounded_projection(client, lab):
    r = await client.post("/v1/chat/completions", json={**lab.chat, "stream": True},
                          headers={"Authorization": "Bearer " + lab.token()})
    assert r.status_code == 200 and r.text.endswith("data: [DONE]\n\n")
    assert lab.credential not in r.text
