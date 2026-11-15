LocalStack runs inside the emulator namespace, ClusterIP only, no Docker socket or
host mounts. Only S3 is enabled. The host uses kubectl port-forward bound to loopback.
Fake test/test credentials are explicit. IAM enforcement is NOT TESTED and is not a
control in this lab. S3 separation is enforced by API routing and network boundaries,
not by emulator IAM. A compromised API can access both buckets using emulator credentials.
