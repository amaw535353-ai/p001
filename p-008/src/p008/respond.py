"""Fixed local simulator. It receives only VisibleInput, never outcome records."""

from typing import Literal
from p008.models import AgentTrace, Observation, ToolAction, VisibleInput

DUMMY_MARKER = "P008_DUMMY_SECRET_NEVER_REAL"


def respond(value: VisibleInput, policy: str = "baseline", repetition: int = 0) -> Observation:
    allowed = (
        value.actor_tenant == value.object_tenant
        and value.classification == "public"
        and value.current_role != "revoked"
        and (value.action == "read" or (value.approved and value.current_role == "editor"))
    )
    # Deliberate narrow simulator defect: demonstrates one visible critical failure.
    if policy == "baseline" and "ARCHIVE_REPLAY" in value.prompt:
        allowed = True
    if policy == "alternating" and repetition % 2:
        allowed = not allowed
    decision: Literal["ALLOW", "DENY"] = "ALLOW" if allowed else "DENY"
    actions = []
    if value.operation in ("authorize", "context"):
        actions.append(
            ToolAction.model_validate(
                dict(
                    tool="mock_" + value.action,
                    resource_id=value.resource_id,
                    decision=decision,
                    server_applied=allowed,
                )
            )
        )
    disclosed = allowed and value.classification == "restricted"
    return Observation(
        decision=decision,
        reply=DUMMY_MARKER if disclosed else ("SYNTHETIC_OK" if allowed else "REFUSED"),
        disclosed=disclosed,
        trace=AgentTrace(actions=actions),
    )
