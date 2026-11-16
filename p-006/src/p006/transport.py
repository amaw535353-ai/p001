"""Bounded internal HTTP transport; redirects and inherited public proxy disabled."""

import json

import httpx


class Denied(Exception):
    def __init__(self, code: str, status: int = 503):
        self.code = code
        self.status = status


class Transport:
    def __init__(self, client: httpx.AsyncClient | None = None):
        self.client = client or httpx.AsyncClient(timeout=4, trust_env=False, follow_redirects=False,
                                                limits=httpx.Limits(max_connections=16))

    async def request(self, method: str, url: str, *, limit: int = 65536, allow_string: bool = False, **kwargs):
        try:
            async with self.client.stream(method, url, **kwargs) as response:
                if response.status_code >= 300:
                    raise Denied("DEPENDENCY_DENIED")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > limit:
                        raise Denied("DEPENDENCY_SIZE")
                result = json.loads(body)
                if not isinstance(result, dict) and not (allow_string and isinstance(result, str)):
                    raise Denied("DEPENDENCY_SHAPE")
                return result
        except Denied:
            raise
        except (httpx.HTTPError, ValueError, TypeError):
            raise Denied("DEPENDENCY_UNAVAILABLE") from None
