# Controlled detection dataset

Twenty rules in `config/detection-rules.json` cover denial bursts, tenant violations, bypass,
unexpected tools/routes, rate/identity abuse, denied secrets, exporter failure, malformed bursts,
replay, injection classification, hash mismatch, denied exports, admin actions, local egress,
model-query volume, workload identity, configuration change and missing controlled events.

Each has an exact signal, minimum count, fixed level, rationale, ID110900–110919 and version1.0.
The source must classify the controlled event/window first; these examples do not implement a
general production anomaly detector. Counts are bounded; a payload's severity cannot set rule level.
`scripts/build-rules.py` compiles the same preconditions into actual Wazuh JSON-decoder rules.

Offline candidate matches are explicitly not Wazuh alerts. Forty semantic positive/benign pairs
test the preconditions; native logtest and manager ingestion test separate product behavior.
Raw synthetic source digests and native alert IDs/levels support investigation. False positives
and negatives are scoped to these pairs, not measured enterprise detection accuracy.
