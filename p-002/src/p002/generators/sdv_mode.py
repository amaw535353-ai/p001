"""Optional SDV CPU single-table amount synthesis; never an authorization oracle."""

import importlib.metadata
import os
from p002.validation import digest


def synthesize(data):
    try:
        from sdv.metadata import Metadata
        from sdv.single_table import GaussianCopulaSynthesizer
        import pandas as pd
    except ImportError as e:
        raise RuntimeError(
            "BLOCKED: optional SDV dependencies absent; use --mode fixtures or install optional SDV CPU lock"
        ) from e
    version = importlib.metadata.version("sdv")
    if version != "2.2.0":
        raise RuntimeError("BLOCKED: SDV version must match tested 2.2.0 pin")
    os.environ.setdefault("SDV_DISABLE_TELEMETRY", "1")
    invoices = [r for r in data["resources"] if r["kind"] == "invoice"]
    amounts = [r["attributes"]["amount_cents"] for r in invoices]
    frame = pd.DataFrame({"amount_cents": amounts})
    metadata = Metadata.detect_from_dataframes(data={"synthetic_invoice_amounts": frame}, infer_keys=None)
    metadata.update_column(
        table_name="synthetic_invoice_amounts", column_name="amount_cents", sdtype="numerical"
    )
    synth = GaussianCopulaSynthesizer(
        metadata, enforce_min_max_values=True, enforce_rounding=True, default_distribution="truncnorm"
    )
    synth.fit({"synthetic_invoice_amounts": frame})
    sample = synth.sample(num_rows=len(invoices))
    corrected = 0
    for r, amount in zip(invoices, sample["synthetic_invoice_amounts"]["amount_cents"], strict=True):
        value = int(round(float(amount)))
        bounded = max(1000, min(100000, value))
        corrected += bounded != value
        r["attributes"]["amount_cents"] = bounded
    # Derived action requests and approvals must remain bound to the changed quote.
    by_resource = {r["id"]: r for r in invoices}
    by_request = {r["id"]: r for r in data["requests"]}
    for request in data["requests"]:
        request["parameters"]["amount_cents"] = by_resource[request["resource_id"]]["attributes"][
            "amount_cents"
        ]
        request["parameters_sha256"] = digest(request["parameters"])
    for approval in data["approvals"]:
        approval["parameters_sha256"] = by_request[approval["request_id"]]["parameters_sha256"]
    data["sdv_report"] = {
        "library": "sdv",
        "version": version,
        "license": "BSL-1.1; review Additional Use Grant",
        "synthesizer": "GaussianCopulaSynthesizer",
        "distribution": "truncnorm",
        "seed_data": "self-created deterministic invoice amounts only",
        "training_sha256": digest(amounts),
        "tables": ["synthetic_invoice_amounts"],
        "fields": ["amount_cents"],
        "rows": len(invoices),
        "fixed_fields": "all identity, tenant, authorization, document and lineage fields; request/approval hashes are deterministically rebound to sampled amounts",
        "corrected_rows": corrected,
        "bounds": [1000, 100000],
        "reproducibility": "schema/statistical; byte equality not claimed",
        "privacy_claim": None,
    }
    return data
