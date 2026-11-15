# Method, triage and epistemic limits

1. Validate source version, graph references and evidence.
2. Derive candidate boundaries; enumerate real modeled edge transitions.
3. Apply inspectable rule predicates, preconditions and exclusions.
4. Generate tenant/owner-specific MODELLED_THREAT / HYPOTHESIS records.
5. Propose owned controls, positive/negative verification and independent review.
6. Record synthetic editorial decisions against an exact model digest.
7. Compare versioned architectures; invalidate old decisions and mappings.

STRIDE labels describe analysis methods. Prompt-sourced R identifiers are risk
references, not findings. Catalog applicability is PROPOSED for matching features;
NOT_APPLICABLE means no matching modeled feature, with a rationale, not absence
of real risk. Missing taxonomy entries are unavailable, never automatically N/A.

Impact is an ordinal business/technical assumption: HIGH for modeled privilege,
confidentiality or continuity consequences; MEDIUM for narrower design uncertainty;
LOW for limited consequences; UNKNOWN where no basis exists. Rules carry the
impact assumption. Exposure retains the source status. Evidence quality means
DIRECT_METADATA (bounded observation), DECLARATION, INFERENCE or UNKNOWN, never
exploitability. Control strength remains unknown. HIGH impact proposes HIGH review
priority; other impacts propose MEDIUM. These are human-review triage, not CVSS,
finding severity, calibrated likelihood or a risk acceptance decision.

A reasoned editorial priority override is stored separately. Acceptance does not
run a test or grant real authority. No output creates CONTROL_TESTED or
FINDING_CONFIRMED. This version refuses findings and executed verification
results entirely; a future independently reviewed evidence contract is needed
before importing those statuses. All planned tests are NOT_TESTED.
