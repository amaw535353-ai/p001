"""Narrow source-secret scan and explicit PyPI release-advisory lookup."""

import argparse
import json
import re
from urllib.request import urlopen
from urllib.error import HTTPError, URLError
from p002.operations import record_run
from p002.scenarios import ROOT


def scan_source():
    patterns = [
        r"AKIA[A-Z0-9]{16}",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"gh[pousr]_[a-zA-Z0-9]{30,}",
        r"sk-proj-[a-zA-Z0-9_-]{30,}",
    ]
    matches = []
    denominator = 0
    for folder in ["src", "config", "docs", "tests", "scripts", "fixtures", "integrations"]:
        for path in (ROOT / folder).rglob("*"):
            if path.is_file() and path.suffix not in [".pyc"] and "__pycache__" not in path.parts:
                denominator += 1
                for pattern in patterns:
                    if re.search(pattern, path.read_text(errors="replace")):
                        matches.append(str(path.relative_to(ROOT)))
    return {
        "id": "source-secret-pattern-scan",
        "status": "FAIL" if matches else "PASS",
        "expected": "no high-risk credential patterns in publishable source",
        "observed": {
            "matching_paths": matches,
            "files_checked": denominator,
            "limitations": "narrow patterns, not comprehensive secret detection",
        },
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dependencies", action="store_true")
    a = p.parse_args()
    rows = [scan_source()]
    if a.dependencies:
        for line in (ROOT / "requirements-sdv.lock").read_text().splitlines():
            if "==" not in line:
                continue
            name, version = line.split("==", 1)
            # PyPI publishes the base release advisory metadata for CPU torch.
            release = version.split("+")[0]
            try:
                with urlopen(f"https://pypi.org/pypi/{name}/{release}/json", timeout=20) as response:
                    data = json.load(response)
                vulns = [
                    {"id": v["id"], "aliases": v.get("aliases", []), "fixed_in": v.get("fixed_in", [])}
                    for v in data.get("vulnerabilities", [])
                    if not v.get("withdrawn")
                ]
                rows.append(
                    {
                        "id": "dependency:" + name,
                        "status": "FAIL" if vulns else "PASS",
                        "expected": "no published PyPI release advisories",
                        "observed": {
                            "name": name,
                            "version": version,
                            "advisories": vulns,
                            "scope": "PyPI metadata only; not a container or complete supply-chain audit",
                        },
                    }
                )
            except (HTTPError, URLError, TimeoutError):
                rows.append(
                    {
                        "id": "dependency:" + name,
                        "status": "BLOCKED",
                        "expected": "PyPI release advisory metadata",
                        "observed": "metadata request unavailable; not a clean bill of health",
                    }
                )
    out = record_run("audit", rows, args="./scripts/audit" + (" --dependencies" if a.dependencies else ""))
    print(out)
    from collections import Counter

    print(dict(Counter(r["status"] for r in rows)))
    return (
        1
        if any(r["status"] == "FAIL" for r in rows)
        else (2 if any(r["status"] == "BLOCKED" for r in rows) else 0)
    )


if __name__ == "__main__":
    raise SystemExit(main())
