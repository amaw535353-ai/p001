#!/usr/bin/env python3
"""Dependency/data alignment and conservative source-secret hygiene checks."""

import ast
import json
import tomllib

from p005.catalogs.atlas import validate
from p005.evidence.safety import DATA, PROJECT, Invalid, load
from p005.modeling.rule_engine import rules

project = tomllib.loads((PROJECT / "pyproject.toml").read_text())
locked = {
    line.split(" --hash=")[0].strip().lower()
    for line in (PROJECT / "requirements.lock").read_text().splitlines()
    if "==" in line
}
for dep in [*project["project"]["dependencies"], *project["project"]["optional-dependencies"]["dev"]]:
    if dep.lower() not in locked:
        raise Invalid("DECLARATION-NOT-IN-HASH-LOCK")
if load(PROJECT / "rules/core.json") != load(DATA / "rules.json"):
    raise Invalid("PACKAGED-RULE-DRIFT")
rules()
validate(PROJECT / "catalogs/ATLAS-pinned.yaml")
# Runtime has no transport/process-execution imports. Test/build scripts are
# reviewed trusted code and intentionally exercise subprocesses.
for path in (PROJECT / "src/p005").rglob("*.py"):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [x.name for x in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            if any(n.split(".")[0] in {"socket", "requests", "httpx", "urllib", "subprocess"} for n in names):
                raise Invalid("RUNTIME-TRANSPORT-OR-EXECUTION-IMPORT")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"exec", "eval", "compile"}
        ):
            raise Invalid("RUNTIME-CODE-EVALUATION")
for folder in ("src", "fixtures", "docs", "examples"):
    for path in (PROJECT / folder).rglob("*"):
        if path.is_file() and path.suffix in (".py", ".md", ".json", ".yaml"):
            text = path.read_text()
            headers = ["-----BEGIN " + kind + "PRIVATE KEY-----" for kind in ("", "RSA ", "EC ", "OPENSSH ")]
            if any(header in text for header in headers):
                raise Invalid("PRIVATE-KEY-MATERIAL-IN-SOURCE")
print(
    json.dumps(
        dict(
            status="PASS",
            checks=[
                "hash-lock alignment",
                "rule synchronization",
                "pinned ATLAS",
                "no runtime transport/execution",
                "narrow private-key source hygiene",
            ],
        )
    )
)
