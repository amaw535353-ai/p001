# Resource ownership
bootstrap.json: namespaces, emulator and emulator boundary policy, applied by bootstrap
before OpenTofu provider discovery. resources.json: tenant resources owned by OpenTofu.
Use project=p001 labels. Kubernetes is not yet runtime-validated on this host.
Pod Security Admission is restricted for tenant namespaces. System CNI and the emulator
are explicit trusted platform exceptions; no host mounts or Docker socket on emulator.
Operator port-forward bypass is not a tenant network permission.
