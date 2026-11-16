import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from p006.transport import Denied


async def test_a01_identity_missing_denied(client, lab):
    response = await client.post("/v1/chat/completions", json=lab.chat)
    assert response.status_code == 401
    assert not lab.calls


async def test_a02_identity_valid_signed_fixture(lab):
    principal = await lab.identity.verify(lab.token())
    assert principal.subject == lab.subject and lab.introspected == 1


async def test_a03_identity_invalid_signature(lab):
    claims = jwt.decode(lab.token(), options={"verify_signature": False})
    wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(claims, wrong, algorithm="RS256", headers={"kid": "fixture-key"})
    with pytest.raises(Denied):
        await lab.identity.verify(token)


async def test_a04_identity_wrong_issuer(lab):
    with pytest.raises(Denied):
        await lab.identity.verify(lab.token(iss="https://attacker.invalid"))


async def test_a05_identity_wrong_audience(lab):
    with pytest.raises(Denied):
        await lab.identity.verify(lab.token(aud="unrelated-client"))


async def test_a06_identity_expired(lab):
    with pytest.raises(Denied):
        await lab.identity.verify(lab.token(exp=int(time.time()) - 1))


async def test_a07_identity_unsafe_algorithm(lab):
    token = jwt.encode({"sub": lab.subject}, "fixture-only-" + "x" * 40, algorithm="HS256")
    with pytest.raises(Denied):
        await lab.identity.verify(token)


async def test_a08_identity_missing_subject(lab, key):
    claims = jwt.decode(lab.token(), options={"verify_signature": False})
    del claims["sub"]
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "fixture-key"})
    with pytest.raises(Denied):
        await lab.identity.verify(token)


async def test_a09_identity_header_impersonation(client, lab):
    response = await client.post("/v1/chat/completions", json=lab.chat,
                                 headers={"Authorization": "Bearer " + lab.token(), "X-User-ID": "other"})
    assert response.status_code == 400 and not lab.calls


async def test_a10_identity_tenant_header(client, lab):
    response = await client.post("/v1/chat/completions", json=lab.chat,
                                 headers={"Authorization": "Bearer " + lab.token(), "X-Tenant-ID": "tenant-b"})
    assert response.status_code == 400


async def test_a11_identity_logout_introspection_fixture(lab):
    token = lab.token()
    await lab.identity.verify(token)
    lab.active = False
    with pytest.raises(Denied):
        await lab.identity.verify(token)


async def test_a12_identity_deactivated_fixture(lab):
    lab.active = False
    with pytest.raises(Denied):
        await lab.identity.verify(lab.token())


async def test_identity_future_nbf(lab):
    with pytest.raises(Denied):
        await lab.identity.verify(lab.token(nbf=int(time.time()) + 100))


async def test_identity_tenant_claim_tampering(lab):
    with pytest.raises(Denied):
        await lab.identity.verify(lab.token(tenant="tenant-b"))


async def test_identity_role_escalation(lab):
    with pytest.raises(Denied):
        await lab.identity.verify(lab.token(p006_roles=["user", "platform-admin"]))


async def test_identity_untrusted_jku(lab, key):
    claims = jwt.decode(lab.token(), options={"verify_signature": False})
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "fixture-key", "jku": "http://other.invalid"})
    with pytest.raises(Denied):
        await lab.identity.verify(token)
    assert not lab.calls


async def test_identity_jwks_cache_does_not_cache_session(lab):
    await lab.identity.verify(lab.token())
    await lab.identity.verify(lab.token())
    assert sum(path.endswith("/certs") for _, path, _ in lab.calls) == 1
    assert lab.introspected == 2


async def test_identity_unknown_subject(lab):
    with pytest.raises(Denied):
        await lab.identity.verify(lab.token(sub="00000000-0000-4000-8000-000000000099"))


async def test_identity_malformed_token(lab):
    with pytest.raises(Denied):
        await lab.identity.verify("invalid.not-a-token")
