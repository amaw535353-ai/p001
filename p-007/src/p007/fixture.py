"""Owned, bounded loopback fixture with server-side tenant/session decisions."""

from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import json
import threading
from uuid import uuid4

from p007.models import Category, Operation, Target

PAGE = b"""<!doctype html><html><head><meta charset="utf-8"><title>P007 synthetic lab</title>
<link rel="icon" href="data:,"></head><body><h1>P007 synthetic control fixture</h1>
<button id="login-a">Synthetic A</button><button id="login-b">Synthetic B</button>
<button id="own">Read A object</button><button id="other">Read B object</button>
<button id="logout">Logout</button><button id="expired">Expired session</button>
<a id="outside" href="https://example.invalid/">Blocked external navigation</a>
<pre id="result">Ready</pre><pre id="unsafe"></pre><script>
const r=document.querySelector('#result');
for (const [id,path] of Object.entries({'login-a':'/session/a','login-b':'/session/b',
own:'/objects/a',other:'/objects/b',logout:'/session/loggedout',expired:'/session/expired'})) {
document.getElementById(id).onclick=async()=>{const x=await fetch(path);r.textContent=x.status+':'+await x.text();};}
document.querySelector('#unsafe').textContent='<img src=x onerror="window.p007Markup=true">';
</script></body></html>"""


@dataclass
class FixtureLease:
    target: Target
    server: HTTPServer
    active: bool = True


@contextmanager
def owned_fixture():
    instance = "fixture-" + uuid4().hex

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            cookie = self.headers.get("Cookie", "")
            session = next(
                (x.split("=", 1)[1] for x in cookie.split("; ") if x.startswith("p007_session=")), None
            )
            body: dict | bytes = {}
            status, mime = 200, "application/json"
            if self.path == "/ui":
                body, mime = PAGE, "text/html; charset=utf-8"
            elif self.path.startswith("/session/"):
                body = {"synthetic": True, "session_state": self.path.rsplit("/", 1)[-1]}
            elif self.path in ("/objects/a", "/objects/b"):
                if session not in ("a", "b"):
                    status, body = 401, {"decision": "DENY", "reason": "no-active-session"}
                elif session != self.path[-1]:
                    status, body = 403, {"decision": "DENY", "reason": "tenant-boundary"}
                else:
                    body = {"decision": "ALLOW", "object": "fabricated-" + session}
            elif self.path == "/model/denied":
                status, body = 403, {"decision": "DENY", "downstream_calls": 0}
            elif self.path == "/health":
                body = {"synthetic": True}
            else:
                status, body = 404, {"decision": "DENY"}
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-P007-Instance", instance)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            if self.path.startswith("/session/"):
                self.send_header(
                    "Set-Cookie",
                    "p007_session=" + self.path.rsplit("/", 1)[-1] + "; HttpOnly; SameSite=Strict; Path=/",
                )
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass  # negative tests deliberately abort refused redirects/requests

    class BoundedServer(ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 4
        slots = threading.BoundedSemaphore(8)

        def get_request(self):
            wire, address = super().get_request()
            wire.settimeout(2)
            return wire, address

        def process_request(self, request, address):
            if not self.slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            super().process_request(request, address)

        def process_request_thread(self, request, address):
            try:
                super().process_request_thread(request, address)
            finally:
                self.slots.release()

    server = BoundedServer(("127.0.0.1", 0), Handler)
    server.timeout = 1
    paths = (
        "/ui",
        "/health",
        "/session/a",
        "/session/b",
        "/session/expired",
        "/session/loggedout",
        "/objects/a",
        "/objects/b",
        "/model/denied",
    )
    categories: tuple[Category, ...] = ("browser", "passive_scan", "api")
    operations = [Operation(path=p, category=c) for p in paths for c in categories]
    target = Target(
        target_id="local-fixture",
        version="web-v1",
        environment="local-lab",
        origin=f"http://127.0.0.1:{server.server_port}",
        service_identity="p007-fixture",
        owner="p007",
        ownership_ref="in-process-lease",
        instance_id=instance,
        allowed_ips=["127.0.0.1"],
        operations=operations,
        capabilities=["browser", "passive_scan", "api"],
    )
    lease = FixtureLease(target, server)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield lease
    finally:
        lease.active = False
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
