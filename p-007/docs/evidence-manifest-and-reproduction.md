# Evidence integrity and reproduction

Each manifest records repository/branch/actual HEAD, dirty state and working-tree
source/lock/config hash; framework, target and environment identities; time/duration;
selected tests/controls, expectation/observation/status; original runner codes;
commands/tool/model/browser settings; P003 reference and decision digests; artifact
path/type/size/hash; redaction omissions; remediation/retest and provenance fields.
The plan snapshot contains fixture data and all selected definitions.

`p007 evidence verify --run <id>` validates contracts, plan digest, result identities,
artifact hashes/sizes, missing/modified files, and manifest/result agreement.
Traversal/symlinks and collisions fail closed. A valid SHA256 shows consistency
against the recorded digest; an attacker who can rewrite the manifest can rewrite
its hashes. No signature, author identity, trusted timestamp or WORM store is claimed.

`p007 reproduce --run <id> --test <id> --repetitions 2` checks source identity and
uses recorded offline inputs, not the current catalog. It creates new evidence,
compares normalized status/observation and sample outcomes, and preserves the original.
Changed source refuses reproduction. External tool commands need regenerated configs
and fresh authorization; ephemeral native paths are not replayed blindly.

Behavior oracles run before redaction, so disclosure cannot be hidden to create PASS.
Credential keys, Bearer values and synthetic secret/token/cookie markers are removed
before persistence. Raw prompts/native logs are omitted by default; safe structured
sample fields and hashes remain. Do not commit ignored runtime evidence.
