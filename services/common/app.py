"""P-001 deterministic synthetic services. No model or production credentials."""
import hashlib
import json
import os
import re
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, build_opener, ProxyHandler
from urllib.error import HTTPError

TENANT = os.environ.get("P001_TENANT", "tenant-a")
MODE = os.environ.get("P001_MODE", "api")
MAX_BODY = 4096
LOCAL_HTTP = build_opener(ProxyHandler({}))

def infer(prompt):
    return {"simulator": True, "model": "p001-deterministic-v1",
            "digest": hashlib.sha256(prompt.encode()).hexdigest()[:16]}

def authorized(token, tenant):
    import hmac
    return hmac.compare_digest(token, "Bearer p001-fixture-" + tenant)

def object_key(value):
    if not re.fullmatch(r"fixture-[a-z0-9-]{1,40}", value):
        raise ValueError("invalid synthetic object key")
    return value

def s3():
    endpoint = os.environ["P001_S3_ENDPOINT"]
    # Fail closed: never fall back to AWS endpoint/credential discovery.
    if endpoint != "http://localstack.emulator.svc.cluster.local:4566":
        raise ValueError("unapproved emulator endpoint")
    import boto3
    from botocore.config import Config
    return boto3.client("s3", endpoint_url=endpoint, aws_access_key_id="test",
                        aws_secret_access_key="test", region_name="us-east-1",
                        config=Config(proxies={}, s3={"addressing_style": "path"}, retries={"max_attempts": 1}))

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, data):
        raw = json.dumps(data, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Correlation-ID", self.cid)
        self.end_headers()
        self.wfile.write(raw)
        # Allowlist log fields: never log prompts, objects, authorization, paths or query strings.
        print(json.dumps({"event": "request", "status": status, "tenant": TENANT,
                          "service": MODE, "correlation_id": self.cid}), flush=True)

    def handle_request(self):
        candidate = self.headers.get("X-Correlation-ID", "")
        self.cid = candidate if re.fullmatch(r"[a-zA-Z0-9-]{1,64}", candidate) else str(uuid.uuid4())
        if self.path in ("/healthz", "/readyz") and self.command == "GET":
            return self.reply(200, {"status": "ok", "simulator": True, "service": MODE})
        if MODE == "api" and not authorized(self.headers.get("Authorization", ""), TENANT):
            return self.reply(403, {"error": "denied"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_BODY:
                return self.reply(413, {"error": "body limit"})
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("object required")
            if self.command == "POST" and self.path == "/infer":
                prompt = body.get("prompt", "")
                if not isinstance(prompt, str) or len(prompt) > 1024:
                    raise ValueError("invalid prompt")
                if MODE == "mock":
                    return self.reply(200, infer(prompt))
                req = Request("http://mock:8080/infer", json.dumps({"prompt": prompt}).encode(),
                              {"Content-Type": "application/json", "X-Correlation-ID": self.cid})
                with LOCAL_HTTP.open(req, timeout=3) as response:
                    return self.reply(200, json.load(response))
            if MODE == "api" and self.path.startswith("/objects/"):
                key = object_key(self.path.removeprefix("/objects/"))
                bucket = "p001-" + TENANT
                if self.command == "PUT":
                    # Only a fixed fake marker is accepted; no arbitrary personal data storage.
                    if body != {"marker": "P001-SYNTHETIC-ONLY"}:
                        raise ValueError("synthetic marker required")
                    s3().put_object(Bucket=bucket, Key=key, Body=json.dumps(body).encode())
                    return self.reply(201, {"stored": True, "tenant": TENANT})
                if self.command == "GET":
                    obj = s3().get_object(Bucket=bucket, Key=key)
                    return self.reply(200, {"tenant": TENANT, "object": json.loads(obj["Body"].read())})
            return self.reply(404, {"error": "not found"})
        except (ValueError, TypeError, json.JSONDecodeError):
            return self.reply(400, {"error": "invalid request"})
        except Exception:
            return self.reply(502, {"error": "upstream unavailable"})

    do_GET = handle_request
    do_POST = handle_request
    do_PUT = handle_request

if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
