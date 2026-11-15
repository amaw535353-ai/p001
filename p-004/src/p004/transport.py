"""The only implemented live egress path: one literal-loopback HTTP connection.

This is not a browser proxy. No DNS, redirect following, cookies or ambient
proxy/auth settings are used. API accepts no arbitrary headers or payloads.
"""

import http.client
import socket
from urllib.parse import urlsplit

from p004.policy import Denied, Guard


class GuardedHTTP:
    def __init__(self, guard: Guard):
        self.guard = guard

    def request(self, url: str, method="GET", *, depth=0):
        guard = self.guard
        if not guard.lock.acquire(blocking=False):
            raise Denied("CONCURRENCY-LIMIT")
        connection = None
        try:
            target = guard.check(url, method, depth)
            p = urlsplit(target)
            remaining = guard.max_seconds - (guard.clock() - guard.started)
            # Pass numeric address directly to AF_INET socket: no getaddrinfo / DNS.
            guard.check(target, method, depth)  # fresh P003 check on the actual connect path
            wire = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                wire.settimeout(min(3.0, remaining))
                wire.connect(("127.0.0.1", p.port))
                if wire.getpeername()[0] != "127.0.0.1":
                    raise Denied("PEER-MISMATCH")
                guard.check(target, method, depth, consume=True)  # recheck after connect, before request
                connection = http.client.HTTPConnection("127.0.0.1", p.port, timeout=min(3.0, remaining))
                connection.sock = wire
                connection.request(method, p.path, headers={"User-Agent": "p004-local-readonly/1.0"})
                response = connection.getresponse()
                # Bodies are discarded. Bounded reads preserve resource limits and no token/HTML retention.
                total = 0
                while True:
                    if guard.clock() - guard.started >= guard.max_seconds:
                        raise Denied("DURATION-LIMIT")
                    chunk = response.read(4096)
                    total += len(chunk)
                    if total > 64_000:
                        raise Denied("RESPONSE-SIZE-LIMIT")
                    if not chunk:
                        break
                if response.getheader("X-P004-Instance") != guard.owned.instance_id:
                    raise Denied("OWNED-FIXTURE-INSTANCE-MISMATCH")
                if 300 <= response.status < 400:
                    # Never follow or retain Location, even within the same origin.
                    raise Denied("REDIRECT-BLOCKED")
                return dict(
                    url=target,
                    method=method,
                    status=response.status,
                    request_number=guard.used,
                    response_bytes=total,
                )
            finally:
                wire.close()
        except (http.client.HTTPException, OSError) as exc:
            raise Denied("HTTP-TRANSPORT-FAILED") from exc
        finally:
            if connection:
                connection.close()
            guard.lock.release()
