# Method and claim limits

1. Enumerate explicit local inputs under a chosen root. Reject symlinks, traversal,
   nonregular files, oversized inputs, YAML aliases/unsafe tags and duplicate keys.
2. Parse declarations without execution, shell expansion or remote references.
   P-001 inventory uses actual manifests and a reviewed source fingerprint contract;
   a changed route contract fails closed for review. Python decorators are candidates.
3. Preserve tenant/identity distinctions. P-002 imports use its real typed graph
   validator. P-003 imported JSON is governance context, never an approved capability.
4. Make live observations only via fresh P-003 evaluation plus tool transport
   restrictions. Read-only-by-design requests still need a reviewed safe target.
5. Correlate only exact stable identities or an explicit one-to-one reviewed
   mapping. Retain disagreement observations and all source references.
6. Review the graph, candidate crossings and source/API drift as a human. Unknown
   paths, hidden connectors, dynamic code, policies and third-party services remain
   unknown. An endpoint's existence never proves exploitability.

Source, manifest and traffic-fixture text may be attacker-controlled. Prompt-like
instructions, shell snippets, OpenAPI examples and environment expressions are
treated as data. No plugin or discovered command is automatically executed.

Boundaries include caller/API, API/workload credential, API/mock inference,
workload/emulator store, namespace/workload and application/stdout declarations.
These form scoping questions, not a complete trust model or risk register.
