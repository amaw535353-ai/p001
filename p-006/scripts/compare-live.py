#!/usr/bin/env python3
"""Compare only an explicitly started, owned weak fixture and the actual hardened PEP."""

import datetime
import hashlib
import json
import secrets
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def execute(container, script):
    inspection = subprocess.check_output(["docker", "inspect", container], text=True)
    info = json.loads(inspection)[0]
    if info["Config"].get("Labels", {}).get("io.p006.owner") != "p006" or not info["State"]["Running"]:
        raise RuntimeError("owned running profile required")
    result = subprocess.run(["docker", "exec", "-i", container, "python", "-"], input=script,
                            text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def main():
    weak = execute("p006-weak", '''
import json,socket,httpx
from pathlib import Path
c=httpx.Client(trust_env=False)
r=c.post("http://127.0.0.1:8080/v1/chat/completions",json={"model":"local-admin"},headers={"X-Tenant-ID":"tenant-b"})
warning=c.get("http://127.0.0.1:8080/").text
blocked=False
try:
 with socket.create_connection(("198.51.100.1",443),timeout=2):pass
except OSError:blocked=True
print(json.dumps({"accepted":r.status_code==200 and r.json().get("tenant")=="tenant-b" and r.json().get("model")=="local-admin", "warning":"INTENTIONALLY INSECURE" in warning,"egress_blocked":blocked,"default_route":any(x.split()[1]=="00000000" for x in Path("/proc/net/route").read_text().splitlines()[1:])}))
''')
    hard = execute("p006-pep", '''
import json,httpx
r=httpx.post("http://127.0.0.1:8080/v1/chat/completions",json={"model":"local-admin"},headers={"X-Tenant-ID":"tenant-b"},trust_env=False)
print(json.dumps({"denied":r.status_code==400 and r.json().get("error")=="IDENTITY_HEADER_DENIED"}))
''')
    conditions = [("W01", weak["accepted"] and weak["warning"], "Actual opted-in weak fixture trusts synthetic caller tenant/model and displays warning"),
                  ("W02", hard["denied"], "Same forged tenant/model request is denied by actual hardened server enforcement"),
                  ("N01-weak", weak["egress_blocked"] and not weak["default_route"], "Actual weak network has no default route and denies off-network connection")]
    results = [{"test_id": id, "status": "PASS" if condition else "FAIL", "observation": observation}
               for id, condition, observation in conditions]
    run_id = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    directory = ROOT / "evidence" / run_id
    directory.mkdir(mode=0o700)
    payload = json.dumps({"schema_version": "p006-comparison-v1", "results": results}, indent=2) + "\n"
    (directory / "comparison.json").write_text(payload)
    (directory / "manifest.json").write_text(json.dumps({"comparison.json": hashlib.sha256(payload.encode()).hexdigest()}) + "\n")
    print(json.dumps({"run": str(directory.relative_to(ROOT)), "results": results}, indent=2))
    raise SystemExit(1 if any(r["status"] == "FAIL" for r in results) else 0)


if __name__ == "__main__":
    main()
