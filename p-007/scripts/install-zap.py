#!/usr/bin/env python3
"""Install the reviewed ZAP distribution into P007-owned .tools, with digest check."""

import hashlib
import os
from pathlib import Path
import tarfile
import urllib.request

root = Path(__file__).resolve().parents[1] / ".tools"
archive = root / "ZAP_2.17.0_Linux.tar.gz"
url = "https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz"
expected = "efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a"
if not archive.exists():
    if os.environ.get("P007_OFFLINE") == "1":
        raise SystemExit("BLOCKED: offline ZAP archive absent")
    with urllib.request.urlopen(url, timeout=180) as response, archive.open("xb") as out:
        while chunk := response.read(1048576):
            out.write(chunk)
if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
    raise SystemExit("BLOCKED: ZAP distribution digest mismatch")
target = root / "ZAP_2.17.0"
if not target.exists():
    with tarfile.open(archive) as stream:
        stream.extractall(root, filter="data")
print("ZAP 2.17.0 archive verified; live gate requires an actual passive run")
