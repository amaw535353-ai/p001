#!/usr/bin/env python3
"""Record installed package names/versions/license metadata; never environment values."""

import importlib.metadata
import json
import subprocess

from p007.safety import PROJECT


def python_packages():
    return sorted(
        [
            {
                "name": d.metadata["Name"],
                "version": d.version,
                "license": d.metadata.get("License-Expression")
                or (d.metadata.get("License") or "UNKNOWN").splitlines()[0],
            }
            for d in importlib.metadata.distributions()
        ],
        key=lambda x: x["name"].lower(),
    )


if __name__ == "__main__":
    packages = []
    for path in (PROJECT / ".tools/node/node_modules").rglob("package.json"):
        try:
            data = json.loads(path.read_text())
            if data.get("name") and data.get("version"):
                packages.append(
                    {
                        "name": data["name"],
                        "version": data["version"],
                        "license": data.get("license", "UNKNOWN"),
                    }
                )
        except (ValueError, UnicodeError):
            continue
    worker = PROJECT / ".tools/inspect/bin/python"
    inspect = json.loads(
        subprocess.check_output(
            [
                str(worker),
                "-c",
                "import importlib.metadata,json; print(json.dumps(sorted([{'name':d.metadata['Name'],'version':d.version,'license':d.metadata.get('License-Expression') or (d.metadata.get('License') or 'UNKNOWN').splitlines()[0]} for d in importlib.metadata.distributions()],key=lambda x:x['name'])))",
            ],
            text=True,
        )
    )
    result = {
        "core_python": python_packages(),
        "inspect_isolated_python": inspect,
        "node_packages": sorted(
            {(x["name"], x["version"]): x for x in packages}.values(), key=lambda x: x["name"]
        ),
        "zap": {
            "version": "2.17.0",
            "license": "Apache-2.0",
            "archive_sha256": "efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a",
        },
        "limit": "Metadata inventory, not legal advice or a vulnerability audit. UNKNOWN entries require review before redistribution.",
    }
    (PROJECT / "docs/dependency-inventory.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    print("Recorded Python and Node metadata inventory")
