"""Owned loopback UI/API fixture, never launched by offline import or discovery."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from uuid import uuid4

from p004.policy import OwnedTarget
from p004.safety import Invalid, contained

PAGE = b"""<!doctype html><meta charset="utf-8"><title>P004 Synthetic</title>
<h1>Synthetic tenant-a architecture fixture</h1><div id="result"></div>
<script>fetch('/api/catalog').then(r=>r.json()).then(d=>{
document.getElementById('result').textContent=d.service;});</script>"""


def server(port=0):
    instance = "fixture-" + uuid4().hex

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if self.path == "/":
                status, body, mime = 200, PAGE, "text/html"
            elif self.path == "/api/catalog":
                status, body, mime = (
                    200,
                    b'{"service":"p004-synthetic","tenant":"tenant-a"}',
                    "application/json",
                )
            elif self.path == "/health":
                status, body, mime = 200, b'{"status":"ok","synthetic":true}', "application/json"
            else:
                status, body, mime = 404, b'{"error":"unknown"}', "application/json"
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-P004-Instance", instance)
            self.end_headers()
            self.wfile.write(body)

    app = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    app.daemon_threads = True
    owned = OwnedTarget(
        instance_id=instance,
        origin=f"http://127.0.0.1:{app.server_port}",
        tenant_id="tenant-a",
        safe_paths=["/", "/api/catalog", "/health"],
        synthetic_only=True,
    )
    return app, owned


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Start an owned synthetic local fixture; does not approve discovery"
    )
    parser.add_argument("--port", type=int, default=8764)
    parser.add_argument("--owned-out", required=True)
    args = parser.parse_args()
    output = Path(args.owned_out).absolute()
    contained(output.parent, output.name)
    if output.exists():
        raise Invalid("OWNERSHIP-FILE-EXISTS")
    app, owned = server(args.port)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(owned.model_dump(), indent=2) + "\n")
    output.chmod(0o600)
    print("Owned fixture ready; P003 approval still required", flush=True)
    try:
        app.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.server_close()


if __name__ == "__main__":
    main()
