# Candidate threat scenarios and assumptions
37 risks are candidate scenarios; 116 P-IDs form a roadmap; 160 numbered entries are
potential tools/targets, not mandatory installations. P-001 establishes a reusable
platform, not 37 deliberate weaknesses or completed assessments.

| Candidate risk | Applicability / future hypothesis |
|---|---|
| #1 workload identity | Verify identity boundaries and credential scope; no federated identity is assumed |
| #15 inference-runtime exposure | Determine who can reach the simulator and whether controls match intended flows |
| #18 resource abuse | Assess whether bounded requests and pod resources meet a defined workload budget |
| #35 tenant isolation | Independently test caller, namespace and object separation assumptions |
| #36 supply-chain integrity | Trace pinned artifacts, dependency provenance, update and rebuild behavior |
| #37 recovery | Assess ownership-safe teardown, drift restoration and reproducible rebuild |

These are future assessment hypotheses, with no confirmed severity or finding.
Assumptions: trusted operator and Docker host, public synthetic test fixtures, no
production secrets, disposable S3 objects and local state, no real AWS parity.
