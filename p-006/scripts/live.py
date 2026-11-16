#!/usr/bin/env python3
"""Owned integration checks, bounded network faults and sanitized local outputs."""

import datetime
import hashlib
import json
import secrets
import subprocess
from pathlib import Path

from p006.models import digest

ROOT = Path(__file__).resolve().parents[1]
RESULTS = []


def run(args):
    return subprocess.run(args, cwd=ROOT, text=True, capture_output=True)


def probe(mode="all"):
    result = run(["docker", "compose", "-p", "p006", "--profile", "tools", "run", "--rm", "-T", "--no-deps", "tester", mode])
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])["results"]
    except (ValueError, IndexError, KeyError):
        return [{"test_id": "probe-startup", "status": "BLOCKED", "observation": "Tester failed before sanitized output"}]


def network_checks():
    script = '''
import json,socket
from pathlib import Path
result={}
for host,port in [("pep",8080),("keycloak",8080),("opa",8181),("vault",8200),("litellm",4000),("model",8000),("198.51.100.1",443)]:
 try:
  with socket.create_connection((host,port),timeout=2):result[host]=True
 except OSError:result[host]=False
result["default_route"] = any(row.split()[1]=="00000000" for row in Path("/proc/net/route").read_text().splitlines()[1:])
print(json.dumps(result))
'''
    r = run(["docker", "exec", "p006-webui", "python", "-c", script])
    try:
        observed = json.loads(r.stdout)
        def record(id, condition, observation):
            RESULTS.append({"test_id": id, "status": "PASS" if condition else "FAIL", "observation": observation})
        record("N01-N05", observed["198.51.100.1"] is False and observed["default_route"] is False,
               "Actual UI has no default route and cannot connect to reserved off-network destination")
        record("N02", observed["pep"] and observed["keycloak"], "UI reaches required PEP/identity destinations")
        record("N03", not observed["opa"] and not observed["vault"] and not observed["litellm"],
               "Actual UI cannot reach policy, secret or gateway services")
        record("N04", not observed["model"], "Actual UI cannot bypass PEP to backend")
    except (ValueError, KeyError):
        RESULTS.append({"test_id": "N01-N05", "status": "BLOCKED", "observation": "UI network probe unavailable"})
    gateway_script = '''
import json,socket
from pathlib import Path
routes=Path("/proc/net/route").read_text().splitlines()[1:]
blocked=False
try:
 with socket.create_connection(("198.51.100.1",443),timeout=2):pass
except OSError:blocked=True
print(json.dumps({"blocked":blocked,"default_route":any(r.split()[1]=="00000000" for r in routes)}))
'''
    result = run(["docker", "exec", "p006-litellm", "python", "-c", gateway_script])
    try:
        observed = json.loads(result.stdout)
        good = observed["blocked"] and not observed["default_route"]
        RESULTS.append({"test_id": "N01-gateway", "status": "PASS" if good else "FAIL",
                        "observation": "Actual gateway has no default route and off-network connection is blocked"})
    except (ValueError, KeyError):
        RESULTS.append({"test_id": "N01-gateway", "status": "BLOCKED", "observation": "Gateway route probe unavailable"})
    events = run(["docker", "logs", "--tail", "150", "p006-pep"])
    identity_observed = False
    for line in (events.stdout + events.stderr).splitlines():
        try:
            event = json.loads(line)
            if event.get("subject") == "00000000-0000-4000-8000-000000000005" and event.get("action") == "chat" and event.get("reason") == "ALLOW":
                identity_observed = True
        except ValueError:
            pass
    RESULTS.append({"test_id": "U02-identity", "status": "PASS" if identity_observed else "FAIL",
                    "observation": "Sanitized actual PEP decision identifies Ben, the user authenticated through Open WebUI"})
    for service in ("webui", "keycloak"):
        data = json.loads(run(["docker", "inspect", "p006-" + service]).stdout)[0]
        bindings = [b for value in data["HostConfig"]["PortBindings"].values() for b in value]
        RESULTS.append({"test_id": "N06-" + service, "status": "PASS" if bindings and all(b["HostIp"] == "127.0.0.1" for b in bindings) else "FAIL",
                        "observation": "Runtime loopback bindings inspected separately from host accessibility"})


def faults():
    for service, network, test_id in [("opa", "policy", "P07"), ("vault", "secrets", "V05"), ("model", "model", "L07")]:
        name, net = "p006-" + service, "p006_" + network
        response = run(["docker", "network", "disconnect", net, name])
        if response.returncode:
            RESULTS.append({"test_id": test_id, "status": "BLOCKED", "observation": "Owned fault injection unavailable"})
            continue
        try:
            records = probe("probe")
            status = "PASS" if records and all(r["status"] == "PASS" for r in records) else "FAIL"
            RESULTS.append({"test_id": test_id, "status": status, "observation": "Real owned dependency disconnected; PEP required to deny safely"})
        finally:
            if run(["docker", "network", "connect", "--alias", service, net, name]).returncode:
                raise RuntimeError("Owned dependency could not be reconnected")
        recovery = probe("recovery")
        good = recovery and all(r["status"] == "PASS" for r in recovery)
        RESULTS.append({"test_id": test_id + "-recovery", "status": "PASS" if good else "FAIL",
                        "observation": "Fresh request succeeds after owned dependency reconnection"})


def main():
    RESULTS.extend(probe())
    if not any(r["status"] in {"FAIL", "BLOCKED"} for r in RESULTS):
        network_checks()
        faults()
    RESULTS.append({"test_id": "W06", "status": "BLOCKED", "observation": "Merged P007 adapter hard-codes unavailable; descriptor v1 only permits BLOCKED/NOT_TESTED"})
    run_id = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    directory = ROOT / "evidence" / run_id
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    data = {"schema_version": "p006-live-summary-v1", "run_id": run_id,
            "config_sha256": digest(json.loads((ROOT / "config/hardened.json").read_text())),
            "results": RESULTS, "model": "deterministic-local; no real LLM evaluated"}
    payload = json.dumps(data, indent=2) + "\n"
    (directory / "results.json").write_text(payload)
    (directory / "manifest.json").write_text(json.dumps({"results.json": hashlib.sha256(payload.encode()).hexdigest()}, indent=2) + "\n")
    counts = {status: sum(r["status"] == status for r in RESULTS) for status in ["PASS", "FAIL", "BLOCKED", "NOT_TESTED", "INCONCLUSIVE"]}
    print(json.dumps({"run": str(directory.relative_to(ROOT)), "counts": counts, "results": RESULTS}, indent=2))
    raise SystemExit(1 if counts["FAIL"] else 2 if counts["BLOCKED"] > 1 else 0)


if __name__ == "__main__":
    main()
