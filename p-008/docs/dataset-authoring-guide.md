# Authoring, review and retirement

1. Define a fictional scenario with a bounded attacker capability and trust level.
2. Author inputs and expected outcomes independently; give a concrete basis and
   distinguish intended policy from an actual observed control.
3. Assign stable IDs, lineage, task/scorer versions, dimensions and limitations.
4. Record generator seed/source hash/commit or immutable upstream source and license.
5. Run schema, quality, split and oracle checks; inspect every failed gate.
6. Freeze a new dataset version. Never update an existing frozen version in place.

Changes to labels, task logic or rubric require a new reviewed version. Retiring
samples creates a new manifest; retain the historical dataset and explain removed
IDs. Ambiguous/disputed labels block freezing until reviewed; a HumanAdjudication
record tracks old/new outcome digests, reason, reviewer and evidence. The code
requires evidence for an accepted human decision; it cannot prove a person actually
performed the review. Do not fabricate human review records.

Only Risk #21 is formally mapped here, on eight integrity examples. Other families
remain unmapped to the absent 37-risk source taxonomy. Add mappings only with the
actual source and a defensible scenario relationship.
