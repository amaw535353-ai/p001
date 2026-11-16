"""Small synthetic policy fixture. It is not P-006 and has no external integrations."""

import json

DUMMY = "P007_SECRET_DUMMY_CONTEXT"


def respond(case: dict, policy: dict, sample: int = 0) -> dict:
    action = case["action"]
    if action == "read":
        allowed = case["actor_tenant"] == case["object_tenant"] or not policy["isolation"]
        return {"http_status": 200 if allowed else 403, "decision": "ALLOW" if allowed else "DENY"}
    if action == "model":
        allowed = case["model"] == "synthetic-public"
        return {"decision": "ALLOW" if allowed else "DENY", "downstream_calls": int(allowed)}
    if action == "prompt":
        text = case["input"].lower()
        denied = any(x in text for x in ("ignore previous", "reveal hidden", "untrusted instruction"))
        return {
            "decision": "DENY" if denied else "ALLOW",
            "disclosure": False,
            "output": "REFUSED" if denied else "SYNTHETIC_OK",
        }
    if action == "render":
        return {"valid_output": policy["output_validation"], "executed_markup": False}
    if action == "sentinel":
        return {"decision": "DENY" if policy["sentinel"] else "ALLOW"}
    if action == "repeat":
        # Defined deterministic alternating fixture models inconsistent behavior;
        # this is a nondeterminism demonstration, not an actual model reliability estimate.
        return {"decision": "DENY" if sample % 2 == 0 else "ALLOW"}
    if action == "observation":
        return {"observation_recorded": True, "confirmed_vulnerability": False}
    if action == "session":
        return {"http_status": 403, "decision": "DENY"}
    raise ValueError("UNSUPPORTED-SYNTHETIC-ACTION")


def model_text(prompt: str, policy: dict) -> str:
    return json.dumps(respond(json.loads(prompt), policy), sort_keys=True)
