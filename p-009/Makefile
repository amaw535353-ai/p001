SHELL := /bin/bash
P := .venv/bin/python
PROFILE ?= core
.PHONY: doctor validate up down status cleanup test test-offline verify lint typecheck demo export retention-audit evidence-verify test-live test-otel test-openllmetry test-langfuse test-wazuh test-correlation test-redaction test-integrity import-p007 import-p008 timeline
doctor validate status demo export retention-audit evidence-verify:
	@./scripts/p009 $@
up:
	@./scripts/p009 up --profile $(PROFILE)
down:
	@./scripts/p009 down
cleanup:
	@./scripts/p009 cleanup --confirm '$(CONFIRM)'
test:
	$(P) -m pytest -m 'not live'
test-offline:
	PYTHONPATH=tests/no-network:src $(P) -m pytest -m 'not live'
test-live:
	./scripts/p009 test-live --profile $(PROFILE)
test-otel test-openllmetry:
	./scripts/p009 test-live --profile core
test-langfuse:
	./scripts/p009 test-live --profile langfuse
test-wazuh:
	./scripts/p009 test-live --profile wazuh
test-correlation:
	$(P) -m pytest tests/test_correlation.py
test-redaction:
	$(P) -m pytest tests/test_privacy.py
test-integrity:
	$(P) -m pytest tests/test_archive.py
lint:
	.venv/bin/ruff check src scripts tests
	.venv/bin/ruff format --check src scripts tests
typecheck:
	.venv/bin/mypy src
verify: validate lint typecheck test-offline
	$(P) scripts/build-rules.py --check
	$(P) scripts/build-schemas.py --check
import-p007 import-p008:
	./scripts/p009 $@ --file '$(FILE)' $(if $(RUN_ROOT),--run-root '$(RUN_ROOT)')
timeline:
	./scripts/p009 timeline --key $(if $(REQUEST_ID),request_id,trace_id) --value '$(or $(REQUEST_ID),$(TRACE_ID))'
