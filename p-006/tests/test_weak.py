import httpx
import pytest

from p006.models import Profile
from p006.pep import Engine
from p006.weak import WARNING, create_app


def test_w03_weak_factory_opt_in(monkeypatch):
    monkeypatch.delenv("P006_WEAK_CONFIRM", raising=False)
    with pytest.raises(RuntimeError):
        create_app()


async def test_w01_weak_cross_tenant_header_reproduced(monkeypatch):
    monkeypatch.setenv("P006_WEAK_CONFIRM", "local-synthetic-only")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://weak") as client:
        r = await client.post("/v1/chat/completions", json={"model": "local-admin"},
                              headers={"X-Tenant-ID": "tenant-b"})
        assert r.status_code == 200 and r.json()["tenant"] == "tenant-b"
        assert r.json()["warning"] == WARNING and r.json()["model"] == "local-admin"


async def test_w02_weak_same_attack_hardened_denied(client, lab):
    r = await client.post("/v1/chat/completions", json={**lab.chat, "model": "local-admin"},
                          headers={"X-Tenant-ID": "tenant-b", "Authorization": "Bearer " + lab.token()})
    assert r.status_code == 400 and not lab.calls


def test_w04_weak_profile_cannot_enter_hardened_engine(profile, lab):
    data = profile.model_dump()
    data["name"] = "vulnerable-lab"
    with pytest.raises(ValueError):
        Engine(Profile.model_validate(data), lab.identity, lab.engine.policy, lab.engine.vault, lab.engine.gateway)


async def test_weak_ui_warning(monkeypatch):
    monkeypatch.setenv("P006_WEAK_CONFIRM", "local-synthetic-only")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://weak") as client:
        assert WARNING in (await client.get("/")).text
