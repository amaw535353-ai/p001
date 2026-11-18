"""Generate checked-in schema views of the strict local contracts."""

import argparse
import json

from p010.langfuse import Binding
from p010.models import (
    RECORDS,
    AcceptanceInput,
    AtlasInput,
    ObservationDraft,
    RemediationInput,
    ReportNarrative,
    Reproduction,
    RetestInput,
    RetestPlanInput,
    RiskInput,
    SeverityInput,
    TraceReference,
    Validation,
)
from p010.oscal import OscalManifest
from p010.reports import Handoff, ReportManifest
from p010.safety import ROOT
from p010.store import AuditEvent, Envelope

SCHEMAS = {
    **RECORDS,
    "record-version": Envelope,
    "audit-event": AuditEvent,
    "reproduction": Reproduction,
    "observation-draft": ObservationDraft,
    "finding-validation": Validation,
    "severity-decision-input": SeverityInput,
    "risk-input": RiskInput,
    "remediation-input": RemediationInput,
    "retest-input": RetestInput,
    "retest-plan-input": RetestPlanInput,
    "risk-acceptance-input": AcceptanceInput,
    "atlas-input": AtlasInput,
    "report-narrative": ReportNarrative,
    "report-manifest": ReportManifest,
    "p010-handoff-v1": Handoff,
    "oscal-manifest": OscalManifest,
    "langfuse-trace": TraceReference,
    "langfuse-binding": Binding,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    failed = False
    for key, model in sorted(SCHEMAS.items()):
        path = ROOT / "schemas" / (key + ".schema.json")
        data = {"$schema": "https://json-schema.org/draft/2020-12/schema", **model.model_json_schema()}
        text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.check:
            if not path.is_file() or path.read_text() != text:
                print(f"Schema drift in {path.name}")
                failed = True
        else:
            path.write_text(text)
    if not failed:
        print(f"{len(SCHEMAS)} P-010 JSON schemas")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
