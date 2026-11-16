#!/usr/bin/env python3
"""Record installed distribution metadata without querying models or credentials."""

import json
import subprocess

from p008.safety import PROJECT, canonical, digest, read_bytes

snippet = """import importlib.metadata as m, json, platform
rows=[]
for d in m.distributions():
    license=d.metadata.get('License-Expression') or d.metadata.get('License')
    if not license:
        license='; '.join(c.removeprefix('License :: ') for c in d.metadata.get_all('Classifier',[]) if c.startswith('License :: ')) or 'UNKNOWN_REVIEW_REQUIRED'
    rows.append({'name':d.metadata['Name'],'version':d.version,'license_metadata':license[:240]})
print(json.dumps({'python':platform.python_version(),'packages':sorted(rows,key=lambda x:x['name'].lower())}))"""
result = {"schema_version": "1.0", "environments": {}}
for name, executable in (
    ("core", PROJECT / ".venv/bin/python"),
    ("tools", PROJECT / ".tools/venv/bin/python"),
):
    if executable.is_file():
        result["environments"][name] = json.loads(
            subprocess.check_output([str(executable), "-c", snippet], text=True)
        )
result["lock_hashes"] = {
    name: digest(read_bytes(PROJECT / name))
    for name in ("requirements.lock", "requirements-tools.lock", "tools/package-lock.json")
}
lock = json.loads((PROJECT / "tools/package-lock.json").read_text())
result["npm_packages"] = [
    {
        "name": name.removeprefix("node_modules/"),
        "version": row.get("version"),
        "license_metadata": row.get("license", "UNKNOWN_REVIEW_REQUIRED"),
        "integrity": row.get("integrity"),
    }
    for name, row in lock["packages"].items()
    if name
]
result["limits"] = (
    "Metadata inventory, not a legal license opinion, SBOM attestation or vulnerability-free claim. See audit report for observed advisories."
)
(PROJECT / "docs/dependency-inventory.json").write_bytes(canonical(result))
print("PASS dependency inventory written")
