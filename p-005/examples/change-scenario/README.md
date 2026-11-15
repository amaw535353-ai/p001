# Versioned architecture change

fixtures/variants/tenant-boundary-change.yaml deliberately adds a synthetic
cross-tenant link and moves one resource outside modeling scope. make demo-offline
produces generated/demo-changed and generated/model-diff.json. Retained IDs do not
retain approval. Review the changed graph, scope and validation prerequisites
independently; no traffic or exploit is run.
