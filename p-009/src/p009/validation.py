"""Structural checks complement actual product validation; they are not runtime proof."""

import subprocess

from p009.config import config
from p009.operate import load_yaml
from p009.safety import ROOT, Invalid, load


def validate():
    cfg = config()
    if len({s.source_id for s in cfg.sources}) != len(cfg.sources):
        raise Invalid("SOURCE-ID-COLLISION")
    compose = load_yaml(ROOT / "compose.yaml")
    if any(not n.get("internal") for n in compose["networks"].values()):
        raise Invalid("PUBLIC-NETWORK")
    for service in compose["services"].values():
        if service.get("labels", {}).get("io.p009.owner") != "p009" or service.get("privileged"):
            raise Invalid("CONTAINER-OWNERSHIP-OR-PRIVILEGE")
        if service.get("network_mode") == "host" or "ALL" not in service.get("cap_drop", []):
            raise Invalid("CONTAINER-SECURITY")
        if any(not p.startswith("127.0.0.1:") for p in service.get("ports", [])):
            raise Invalid("LISTENER-NOT-LOOPBACK")
        if any("docker.sock" in v or "/var/log" in v for v in service.get("volumes", [])):
            raise Invalid("HOST-MOUNT-REFUSED")
    for image in load(ROOT / "config/images.lock.json").values():
        if "@sha256:" not in image or len(image.split("@sha256:")[-1]) != 64:
            raise Invalid("IMAGE-UNPINNED")
    subprocess.run(
        [str(ROOT / ".venv/bin/python"), str(ROOT / "scripts/build-schemas.py"), "--check"], check=True
    )
    return {"status": "PASS", "sources": len(cfg.sources), "native_gates": "separate live tests required"}
