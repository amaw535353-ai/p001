# Integrity threat model and custody limits

Each canonical manifest records source/version, source and observed collection times, exact object
size/hash, correlation/redaction versions and configuration/deployment digests. Its filename embeds
its own digest and sequence; previous digests detect middle-chain changes. Disposable tamper tests
modify object bytes, a manifest and a middle-chain member and require verification failure.

These checks establish consistency with recorded bytes under a trusted local custodian. They do
not establish source truthfulness, author identity, trusted external time, signatures, WORM storage,
legal admissibility, or resistance to a privileged host operator rewriting the entire archive.
Deleting a complete unanchored suffix/all local history is not independently detectable. No
tamper-proof, non-repudiation or forensic-certification claim is made.

Custodian audit records identify authenticated API roles or the local Unix owner, action, outcome,
tenant, time and count. They omit raw payloads/tokens. Audit retention and local clock trust are
explicit limitations. P007's digest assurances are preserved at the same level, never upgraded.
