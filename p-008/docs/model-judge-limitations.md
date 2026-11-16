# Supplementary judge boundary

No real model judge runs by default or during this delivery. `judge_input` wraps
sample text with an untrusted-content marker and a fixed host rubric. It never
forwards outcome records or sealed keys. Judge prompt/configuration identities
participate in comparability. A judge cannot opt into hidden expected outcomes.

`judge_agreement` computes disagreement IDs/agreement for explicitly supplied
human-calibrated records; without evidence it returns NOT_TESTED. Arithmetic tests
use conspicuously synthetic evidence references and do not establish human review.
Human disagreement, ambiguous labels and high-impact decisions require independent
adjudication. A future judge must retain safe rationale and calibration provenance.

The M12 hostile sample tries to replace grading criteria. The demonstration proves
that data cannot edit host configuration; it does not prove that a real LLM judge
would follow the boundary. Semantic judge injection, biased initial criteria,
unrepresentative calibration, collusion and model drift remain residual risks.
