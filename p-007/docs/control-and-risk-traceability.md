# Control and risk traceability

| Control | Defined behavior | Demonstration |
|---|---|---|
| C-tenant | Same-tenant reads and denial sentinel | permitted read, forbidden object, introduced regression |
| C-model | Denial before model invocation | denied model, downstream call count zero |
| C-prompt | Finite local prompt patterns refuse disclosure | direct/indirect injection and hidden-context fixture |
| C-output | Structured output validation and safe rendering | deliberately failing baseline, simulated fix |
| C-session | Session/tenant boundaries | offline case and actual browser/server flows |
| C-observation | Passive alerts remain unconfirmed | synthetic contract and real ZAP observations |

External risk IDs remain empty/UNMAPPED because the full 37-risk map was not supplied.
Local `TH-*` identifiers are synthetic hypotheses, not external inventory claims.
P005 import preserves its actual threat IDs, candidate control IDs, risk references
and MODELLED_THREAT status without promoting them to P007 findings. Its risk subset
is not the missing authoritative taxonomy. See source discovery and acceptance tables.
