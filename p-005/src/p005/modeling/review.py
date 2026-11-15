"""Synthetic editorial ledger, tied to a particular model digest, never authority."""

from p005.domain.schemas import HumanReview, Model
from p005.evidence.safety import Invalid, digest, parse, read, write, canonical, redact


def records(run) -> list[dict]:
    rows = [
        HumanReview.model_validate(parse(line)).model_dump()
        for line in read(run / "review-log.jsonl").splitlines()
        if line.strip()
    ]
    if [r["sequence"] for r in rows] != list(range(1, len(rows) + 1)):
        raise Invalid("REVIEW-SEQUENCE-MISMATCH")
    return rows


def decide(
    run,
    model: Model,
    analysis: dict,
    threat_id: str,
    decision: str,
    role: str,
    reason: str,
    at: str,
    priority: str | None = None,
) -> dict:
    if threat_id not in {t["threat_id"] for t in analysis["threats"]}:
        raise Invalid("UNKNOWN-REVIEW-THREAT")
    model_hash = digest(model.model_dump())
    old = records(run)
    if any(r["model_digest"] != model_hash for r in old):
        raise Invalid("STALE-REVIEW-LOG: reassessment required")
    # Timestamp validation uses the same strict UTC contract as the model.
    from datetime import datetime

    datetime.strptime(at, "%Y-%m-%dT%H:%M:%SZ")
    item = HumanReview.model_validate(
        dict(
            threat_id=threat_id,
            model_digest=model_hash,
            sequence=len(old) + 1,
            reviewer_role=redact(role),
            decision=decision,
            reason=redact(reason),
            at_utc=at,
            priority_override=priority,
        )
    )
    if old and at < old[-1]["at_utc"]:
        raise Invalid("REVIEW-CLOCK-REGRESSION")
    write(
        run / "review-log.jsonl",
        b"".join(canonical(r).replace(b"\n", b"") + b"\n" for r in [*old, item.model_dump()]),
    )
    return item.model_dump()
