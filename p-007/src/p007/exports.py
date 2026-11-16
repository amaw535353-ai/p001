"""Sanitized JSON/JSONL/Markdown/JUnit and P008/P009/P010 handoff exports."""

from collections import Counter
from pathlib import Path
import xml.etree.ElementTree as ET

from p007.models import EvidenceManifest, ReportExport
from p007.safety import Invalid, canonical, digest, read_bytes, safe_path, write_new


def report(manifest: EvidenceManifest, folder: Path) -> ReportExport:
    controls = {}
    for control in sorted({c for r in manifest.results for c in r.control_ids}):
        outcomes = [r.status for r in manifest.results if control in r.control_ids]
        controls[control] = (
            "FAIL" if "FAIL" in outcomes else "PASS" if all(s == "PASS" for s in outcomes) else "INCOMPLETE"
        )
    return ReportExport(
        run_id=manifest.run_id,
        manifest_sha256=digest(read_bytes(folder / "manifest.json")),
        results=manifest.results,
        control_status=controls,
        handoff={
            "contract": "p007-handoff-v1",
            "p008": {"purpose": "small test metadata only, no corpus platform"},
            "p009": {
                "manifest_ref": manifest.run_id + "/manifest.json",
                "artifacts": [a.model_dump(mode="json") for a in manifest.artifacts],
            },
            "p010": {
                "remediation_ref": manifest.remediation_ref,
                "retest_of": manifest.retest_of,
                "result_kind": "synthetic test outcomes; no confirmed client findings",
            },
        },
        provenance=manifest.provenance,
    )


def markdown(manifest: EvidenceManifest) -> str:
    counts = Counter(r.status for r in manifest.results)
    rows = [
        f"# P-007 synthetic run {manifest.run_id}",
        "",
        "Synthetic training laboratory. Human independent verification NOT DEMONSTRATED.",
        "",
        "Results: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())),
        "",
        "| Test | Status | Assertion |",
        "|---|---|---|",
    ]
    rows += [f"| {r.test_id} | {r.status} | {r.assertion.replace('|', '/')} |" for r in manifest.results]
    rows += [
        "",
        f"Remediation reference: {manifest.remediation_ref or 'not supplied'}",
        f"Retest of: {manifest.retest_of or 'not supplied'}",
        "",
        "Limitations:",
    ]
    rows += ["- " + x for x in manifest.limitations]
    rows += ["", "Provenance:"] + [f"- {k}: {v}" for k, v in manifest.provenance.items()]
    return "\n".join(rows) + "\n"


def junit(manifest: EvidenceManifest) -> bytes:
    suite = ET.Element(
        "testsuite",
        name="p007-synthetic-controls",
        tests=str(len(manifest.results)),
        failures=str(sum(r.status == "FAIL" for r in manifest.results)),
        skipped=str(sum(r.status not in ("PASS", "FAIL") for r in manifest.results)),
    )
    for result in manifest.results:
        case = ET.SubElement(
            suite, "testcase", name=result.test_id, classname="p007." + result.runner.adapter
        )
        if result.status == "FAIL":
            ET.SubElement(case, "failure", message=result.assertion).text = result.status
        elif result.status != "PASS":
            ET.SubElement(case, "skipped", message=result.status).text = result.assertion
        ET.SubElement(case, "system-out").text = canonical(result.model_dump(mode="json")).decode()
    return ET.tostring(suite, encoding="utf-8", xml_declaration=True)


def export(manifest: EvidenceManifest, run_folder: Path, output: Path) -> Path:
    safe_path(output)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    value = report(manifest, run_folder)
    files = {
        "report.json": canonical(value.model_dump(mode="json")),
        "report.jsonl": b"".join(canonical(r.model_dump(mode="json")) for r in manifest.results),
        "report.md": markdown(manifest).encode(),
        "junit.xml": junit(manifest),
    }
    for name, data in files.items():
        path = safe_path(output, name)
        if path.exists():
            if read_bytes(path) != data:
                raise Invalid("EXPORT-COLLISION")
        else:
            write_new(path, data)
    return output
