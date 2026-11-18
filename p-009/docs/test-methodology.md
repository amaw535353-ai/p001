# Verification methodology

Offline tests disable socket creation and DNS using `tests/no-network/sitecustomize.py`. They
exercise semantic schemas, privacy classes, source binding, exact/ambiguous correlation, archive
tamper/races/path safety, scope/roles, retention, actual sibling schemas and detection pairs.
They are engineering assertions, not security findings or native product proof.

`make test-live PROFILE=core|langfuse|wazuh` drives actual products and retains a unique ignored
JSON result. Failures and blocked stages exit nonzero and preserve earlier assertions. Collector
health, source SDK execution, export success, downstream ingestion and UI behavior are different
gates. A fixture/schema pass cannot satisfy a native gate. Native tests run sequentially after
stack lifecycle changes settle to avoid measuring a concurrent restart as a product result.

Root `make unit static` is required and retained. No root infrastructure change is made, so P001
Kubernetes/lab-test behavior is not inferred. Counts are reported by layer/category/status and
not added together as a count of independent security controls. Learner competence is separate.
