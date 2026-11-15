"""Fixed endpoint policy and transports. Credentials never enter URLs or argv."""

import base64
import json
import subprocess
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from urllib.error import HTTPError, URLError

ENDPOINTS = {
    "nextcloud": ("http://127.0.0.1:8781", "p002-nextcloud", 80),
    "redmine": ("http://127.0.0.1:8782", "p002-redmine", 3000),
    "label-studio": ("http://127.0.0.1:8783", "p002-label-studio", 8080),
    "p001": ("http://127.0.0.1:8081", "p002-p001-api", 8080),
}


def validate_target(name, url, target):
    if target != "lab" or name not in ENDPOINTS or url != ENDPOINTS[name][0]:
        raise ValueError("only the fixed loopback lab endpoint with --target lab is permitted")
    u = urlsplit(url)
    if u.username or u.password or u.query or u.fragment or u.hostname != "127.0.0.1" or u.scheme != "http":
        raise ValueError("unsafe lab URL")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# This program runs in the owned helper on the internal network. Both endpoint and
# path are constrained before invocation; it never follows a response Location.
REMOTE = """import sys,json,base64
from urllib.request import Request,build_opener,ProxyHandler,HTTPRedirectHandler
from urllib.error import HTTPError
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
q=json.load(sys.stdin)
try:
 r=build_opener(ProxyHandler({}),NoRedirect()).open(Request(q['url'],base64.b64decode(q['body']) if q['body'] is not None else None,q['headers'],method=q['method']),timeout=30)
except HTTPError as e:r=e
b=r.read(4*1024*1024)
print(json.dumps({'status':r.status,'body':base64.b64encode(b).decode(),'headers':{k:v for k,v in r.headers.items() if k.lower() in ['etag','oc-fileid','last-modified','content-type']}}))
"""


def owned_container(name):
    try:
        r = subprocess.run(
            ["docker", "inspect", "--format", '{{index .Config.Labels "owner"}}', name],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return False
    return r.returncode == 0 and r.stdout.strip() == "p002-local-v1"


class Client:
    def __init__(self, name, target, url=None, transport="http", headers=None):
        self.name = name
        self.url = url or ENDPOINTS[name][0]
        validate_target(name, self.url, target)
        if transport not in ["http", "docker"]:
            raise ValueError("unsupported transport")
        self.transport = transport
        self.headers = headers or {}

    def request(self, method, path, body=None, headers=None):
        # Reject absolute URLs, authority-relative paths, controls and encoded traversal.
        if (
            not path.startswith("/")
            or path.startswith("//")
            or "\\" in path
            or any(ord(c) < 32 for c in path)
            or any(x in path.lower() for x in ["..", "%2e", "%2f", "%5c"])
        ):
            raise ValueError("unsafe adapter request path")
        hdr = {**self.headers, **(headers or {})}
        if body is not None and not isinstance(body, bytes):
            body = json.dumps(body).encode()
            hdr.setdefault("Content-Type", "application/json")
        try:
            if self.transport == "docker":
                _, service, port = ENDPOINTS[self.name]
                if not owned_container(service) or not owned_container("p002-http"):
                    raise RuntimeError("BLOCKED: owned lab container/helper absent")
                q = {
                    "url": f"http://{service}:{port}" + path,
                    "method": method,
                    "headers": hdr,
                    "body": base64.b64encode(body).decode() if body is not None else None,
                }
                p = subprocess.run(
                    ["docker", "exec", "-i", "p002-http", "python", "-c", REMOTE],
                    input=json.dumps(q),
                    text=True,
                    capture_output=True,
                    timeout=45,
                )
                if p.returncode:
                    raise RuntimeError(
                        "BLOCKED: local HTTP transport failed; credentials/response not logged"
                    )
                result = json.loads(p.stdout)
                raw = base64.b64decode(result["body"])
                status = result["status"]
                response_headers = result["headers"]
            else:
                try:
                    response = build_opener(ProxyHandler({}), NoRedirect()).open(
                        Request(self.url + path, body, hdr, method=method), timeout=30
                    )
                except HTTPError as e:
                    response = e
                status = response.status
                raw = response.read(4 * 1024 * 1024)
                response_headers = {
                    k: v
                    for k, v in response.headers.items()
                    if k.lower() in ["etag", "oc-fileid", "last-modified", "content-type"]
                }
        except (OSError, URLError, subprocess.TimeoutExpired) as e:
            raise RuntimeError("BLOCKED: fixed local lab transport unavailable") from e
        if 300 <= status < 400:
            raise ValueError("redirect refused; no Location is followed")
        return status, raw, response_headers

    def json(self, method, path, body=None, expected=(200,), headers=None):
        status, raw, _ = self.request(method, path, body, headers)
        if status not in expected:
            raise RuntimeError(
                f"{self.name} API {method} {path.split('?')[0]} unexpected HTTP {status}; response redacted"
            )
        return json.loads(raw) if raw else None


def basic(user, password):
    return "Basic " + base64.b64encode((user + ":" + password).encode()).decode()
