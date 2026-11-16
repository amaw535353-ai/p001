# Security requirements

The 66 acceptance IDs form the versioned requirement set. [Traceability](acceptance-traceability.md)
links each requirement to code-backed assertions or an explicit native gate. Preconditions, objective,
expected behavior, component, boundary, profile and reproduction command are retained in the strict
acceptance catalog. The trusted profile, OPA policy/data, deployment and dependency lock have separate
canonical/file hashes; hash verification proves consistency, not independent assessment.

Security controls configured in manifests remain declarations until measured. Tests record actual status;
BLOCKED/NOT_TESTED/INCONCLUSIVE never count as PASS. Specialist model/agent/RAG risks remain separate.
