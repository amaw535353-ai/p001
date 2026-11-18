# Evidence quality and provenance

```mermaid
flowchart LR
    S["Source-owned bytes"] --> H["Path, length and SHA-256 checks"]
    H --> R["P-010 source record version"]
    A["Artifact absent"] --> U["Reference-only or unavailable"]
    R --> V["Exact evidence link"]
    U --> V
    V --> P["Reviewer and report appendix"]
```

Evidence quality ranges from UNKNOWN or INSUFFICIENT to LIMITED and
CORROBORATED. Record confidence separately. Hashes establish byte consistency.
Source authenticity, trusted time, signer identity and independent custody are
unverified. Reports contain metadata by default. An explicit excerpt
selection is recorded and redacted. Compare original P-007 bytes using an
explicitly selected source run root.
