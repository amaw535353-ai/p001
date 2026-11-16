# P-006 — Secure-by-Default LLM Application Reference Architecture

Synthetic local laboratory. Codex implemented; verification results and remaining gates are in
[validation status](docs/validation-status.md). Human independent reproduction is NOT DEMONSTRATED.
No production readiness, real LLM security, AWS or Kubernetes enforcement claim.

The five source-selected Core technologies are Open WebUI (#138, application), Keycloak (#21,
authentication), OPA (#23, authorization), HashiCorp Vault (#27, secret storage), and LiteLLM (#49,
LLM gateway). P-006 adds a small typed Python PEP, request-proof callback and deterministic backend
to connect their actual enforcement points. It does not replace those products.

```bash
cd p-006
./scripts/setup
make doctor validate
make up                         # hardened by default; generated synthetic credentials only
make status
make test                       # adapter fixtures; no native-service claim
make test-live                  # actual five-product requests, segmentation and fault injection
make up PROFILE=vulnerable-lab CONFIRM=local-synthetic-only
make test-weak compare
make compare-live               # requires explicitly started weak profile
make evidence verify            # unique ignored local engineering output + required root checks
make down
make cleanup CONFIRM=p006-owned-resources
```

UI http://127.0.0.1:8086, Keycloak http://127.0.0.1:8087, opted-in weak UI
http://127.0.0.1:8088. The managed rootless host may suppress port publishing on internal networks;
`make test-live` also drives the real application using fixed internal origins. This is a scripted
HTTP user flow, not a graphical browser assessment. Never add an internet-enabled network to make
ports work. Credentials are generated under host-private `.runtime/`; do not paste them into chat.
The synthetic operator may retrieve its chosen user's password locally from `.runtime/operator/users.json`.
No default/shared password is supplied. `down` removes memory state; use `up` for a fresh bootstrap.

Allow 4 CPUs, 8 GiB RAM and at least 20 GiB free with overlay storage; estimates, not minimums proven
on other hosts. Docker vfs copies full layers and can require substantially more disk (this host
exhausted 63 GB with the full UI image; the pinned official slim image is used). Linux x86_64 and
Python 3.12 are the tested target. Other platforms remain NOT_TESTED.

[Architecture](docs/architecture.md) · [Identity](docs/authentication.md) ·
[Trust boundaries](docs/trust-boundaries.md) · [Vault](docs/vault-secrets.md) ·
[Gateway](docs/litellm-gateway.md) · [Egress](docs/egress-controls.md) ·
[Acceptance matrix](docs/acceptance-traceability.md) · [P007](docs/p007-integration.md) ·
[Limitations](docs/limitations.md) · [Delivery report](docs/delivery-report.md) ·
[Unsolved learner workbook](docs/learner-workbook.md).
