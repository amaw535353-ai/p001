# Risk #21 — manipulation laboratory

Primary formal mapping: **Evaluation, benchmark, and model-judge manipulation**.
Exact practice exercise: “Version synthetic prompts, authorized outcomes, agent
traces, scoring rules, and evaluation sets.” Rationale: “Supports comparable,
auditable evaluation against chosen risk hypotheses.” The absent source documents
are not reconstructed. P-104 remains a separate assessment project.

`make benchmark-integrity RUN=<baseline>` writes 12 original/altered/event triples:

| Case | Mutation | Control |
|---|---|---|
| M01 | Flip expected failure label | Frozen bundle identity |
| M02 | Lower rubric threshold | Scorer identity; critical veto |
| M03 | Omit failed rows | Planned sample reconciliation |
| M04 | Duplicate passing rows | Unique sample/repetition reconciliation |
| M05 | Change evaluator implementation under same version | Implementation digest |
| M06 | Replace judge prompt | Judge/configuration identity |
| M07 | Leak a sealed outcome key | Visible-input projection and canary |
| M08 | Move related examples between splits | Lineage/scenario/template grouping |
| M09 | Omit unfavorable category | Complete expected sample set |
| M10 | Edit recorded plan | Plan digest/run anchor |
| M11 | Present new model version as identical rerun | Model/provider comparison |
| M12 | Judge injection in sample text | Data/config separation; supplementary role |

Every case retains original and altered bytes, digests, detection explanation and
residual limits. Omission/duplicate/category manipulations advertise a misleading
100% rate; the complete baseline is 47/48. Label flip can skew a naive decision-only
score; the independent disclosure oracle still rejects exposed markers. M12 shows
structural isolation, not live judge resistance. An adversary rewriting trusted
anchors, initially dishonest labels/lineage and semantic leakage remain outside
automatic assurance. Human review is necessary.
