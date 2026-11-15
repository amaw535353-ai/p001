# Threat model and bounded assurances

SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING

Protected assets: exact approved specification, separation of fictional roles,
review-evidence integrity, stop state, tenant labels, evidence confidentiality and
clear source attribution. Adversaries include mistaken operators and manipulated
local input files. A malicious filesystem owner, actual external tenant attacker,
legal impostor, compromised host or noncompliant future scanner is outside the
trusted local process boundary; none is proven safe by a hash chain.

| Failure hypothesis | Mechanical control and test | Residual human requirement |
|---|---|---|
| Approval reused after scope change | Exact digest/version and fresh review; stale replay tests | Review meaning of amendment |
| Self-approval | Four role references; requestor approval rejected | Authenticate distinct real people elsewhere |
| Exclusion bypass | Overrides tested with otherwise valid approval | Choose appropriate exclusions |
| Ambiguous target expansion | Percent/IDNA/port/path/CIDR/IP tests; no DNS | Verify ownership/provider constraints |
| Stop races activation/check | SQLite writer ordering; concurrent approve/suspend test | Ensure actual runner stops |
| Evidence changed | Content and file hashes; deletion/whitespace tests | Independently verify source authenticity |
| Log leakage | Sanitized decision references and rejection tests | Review arbitrary text for PII |
| Optional sync touches unrelated resources | Marker/project/journal guards and no DELETE | Operate only owned local Redmine |

No vulnerability assessment was performed on a real AI system. Candidate risks and
planned AISVS references are not findings. Human interpretation and G1–G4 remain
unfilled.
