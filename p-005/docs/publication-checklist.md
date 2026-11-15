# Publication and license review checklist

No push, repository creation, publication or external account connection occurred.
Review this checklist independently before sharing or publishing anything.

- [ ] Inspect branch/diff and preserve prior project behavior.
- [ ] Review generated reports for synthetic-only scope and arbitrary sensitive data.
- [ ] Verify manifests and inspect sanitizer limitations; hashes are not signatures.
- [ ] Confirm model hypotheses, proposed controls and NOT_TESTED plans stay distinct.
- [ ] Review ATLAS Apache-2.0 notice, source pin and dependency/transitive licenses.
- [ ] Resolve the existing repository's overall licensing before redistribution.
- [ ] Keep generated/, evidence/, .venv/ and local configuration out of commits.
- [ ] Supply authoritative taxonomy before claiming full 37-risk validation.
- [ ] Verify any future native tool against actual installed schemas and fixtures.
- [ ] Review exclusions, source evidence and fresh authorization for later testing.
- [ ] Keep human signatures blank and learner G1–G4 UNVERIFIED.
- [ ] Reproduce in a new clean checkout/environment; do not infer CI/publication success.

No aggressive cleanup command is provided. Archive needed evidence first. Remove
only a positively identified, P-005-owned generated run after separate explicit
selection; never remove predecessor data, shared caches or global Docker state.
Rollback consists of discarding only the newly added p-005/ source changes after
review, or switching back to the unchanged base while preserving wanted outputs.
