# Inspected foundation contracts

SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING

P-001 adapter reads infra/kubernetes/resources.json and scripts/lab-up, verifies
owned ClusterIP service labels and the two explicit tenant API forward declarations,
and records full current Git HEAD plus inventory/script hashes. It emits /readyz
loopback endpoint proposals with included=false. It never queries Kubernetes,
redeploys infrastructure or infers policy enforcement from manifests. The actual
source contract test executes against the sibling; live runtime validation by P-003
is NOT TESTED. The earlier foundation doctor identified missing delegated rootless
cgroups; P-003 does not try to elevate privileges or alter that host.

P-002 adapter invokes only the installed sibling Python validator on an existing
generated baseline. load_dataset/verify_files enforce schema, graph, synthetic
provenance and manifest hashes; SDV mode is not imported. It returns tenants,
unassigned fictional role labels, asset classifications and scenario metadata as
proposals. Its ExpectedDecision application-permission oracle is explicitly excluded
from P-003 PreflightAuthorizationDecision. No approval is imported from P-002.
The actual standard dataset and validator were tested; this is a filesystem/data
integration, not a live platform authorization claim.

Both adapters are optional: standalone demo/test/evaluation requires neither sibling.
Absent sibling prerequisites produce a clear operation error; optional sibling tests
skip and remain distinct from passes. Future P-004–P-010 runners can read the stable
engagement-policy.json contract, but must independently bind current ledger state,
revocation, telemetry and actual execution controls. These projects are not built.
