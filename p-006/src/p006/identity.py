"""Keycloak JWT verification plus online introspection; no identity-header trust."""

import time

import jwt
from jwt.algorithms import RSAAlgorithm

from p006.models import Principal, Profile
from p006.transport import Denied, Transport


class Identity:
    def __init__(self, profile: Profile, transport: Transport, client_secret: str):
        self.profile = profile
        self.http = transport
        self.client_secret = client_secret
        self.keys: dict = {}
        self.loaded_at: float = 0
        self.refreshed_at: float = 0

    async def verify(self, token: str) -> Principal:
        try:
            if len(token) > 8192:
                raise ValueError()
            header = jwt.get_unverified_header(token)
            if set(header) - {"alg", "typ", "kid"} or header.get("alg") != "RS256":
                raise ValueError()
            kid = header.get("kid")
            if not isinstance(kid, str) or not 1 <= len(kid) <= 128:
                raise ValueError()
            now = time.monotonic()
            if now - self.loaded_at > 30 or (kid not in self.keys and now - self.refreshed_at > 2):
                self.refreshed_at = now
                jwks = await self.http.request("GET", self.profile.identity.jwks_url)
                keys = jwks.get("keys")
                if not isinstance(keys, list) or not 1 <= len(keys) <= 64:
                    raise ValueError()
                valid = [k for k in keys if k.get("kty") == "RSA" and k.get("use") == "sig"
                         and k.get("alg") == "RS256" and isinstance(k.get("kid"), str)]
                if len({k["kid"] for k in valid}) != len(valid):
                    raise ValueError()
                self.keys = {k["kid"]: RSAAlgorithm.from_jwk(k) for k in valid}
                if any(key.key_size < 2048 for key in self.keys.values()):
                    raise ValueError()
                self.loaded_at = now
            if kid not in self.keys:
                raise ValueError()
            claims = jwt.decode(token, self.keys[kid], algorithms=["RS256"],
                                issuer=self.profile.identity.issuer,
                                audience=self.profile.identity.audience, leeway=0,
                                options={"require": ["sub", "iss", "aud", "exp", "nbf", "iat",
                                                     "jti", "sid", "tenant", "p006_roles", "azp"]})
            if claims["azp"] != "open-webui" or claims["exp"] - claims["iat"] > 300:
                raise ValueError()
            principal = next(p for p in self.profile.principals if p.subject == claims["sub"])
            if (not principal.enabled or claims["tenant"] != principal.tenant
                    or not isinstance(claims["p006_roles"], list)
                    or set(claims["p006_roles"]) != set(principal.roles)):
                raise ValueError()
            active = await self.http.request("POST", self.profile.identity.introspection_url,
                                             data={"token": token, "client_id": "p006-pep",
                                                   "client_secret": self.client_secret})
            if active.get("active") is not True or active.get("sub") != principal.subject:
                raise ValueError()
            return principal
        except Denied:
            raise
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, StopIteration, AttributeError):
            raise Denied("IDENTITY_DENIED", 401) from None
