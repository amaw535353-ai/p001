SHELL := /bin/bash
TARGET ?= offline-demo
PROFILE ?= offline
VARIANT ?= baseline
.PHONY: setup doctor validate catalog plan run compare reproduce evidence-verify report test test-live lint typecheck schemas demo verify cleanup
setup:
	./scripts/setup
doctor validate catalog:
	./scripts/p007 $@
plan:
	./scripts/p007 plan --target '$(TARGET)' --profile '$(PROFILE)' --variant '$(VARIANT)'
run:
	./scripts/p007 run --target '$(TARGET)' --profile '$(PROFILE)' --variant '$(VARIANT)'
compare:
	./scripts/p007 compare --baseline '$(BASELINE)' --current '$(CURRENT)' $(if $(RULE),--rule '$(RULE)',)
reproduce:
	./scripts/p007 reproduce --run '$(RUN)' --test '$(TEST)'
evidence-verify:
	./scripts/p007 evidence verify --run '$(RUN)'
report:
	./scripts/p007 report --run '$(RUN)'
test:
	.venv/bin/python -m pytest tests -m 'not live'
test-live:
	.venv/bin/python -m pytest tests -m live
lint:
	.venv/bin/python -m ruff check src tests scripts
typecheck:
	.venv/bin/python -m mypy src/p007
schemas:
	.venv/bin/python scripts/build-schemas.py --check
demo:
	.venv/bin/python scripts/demo.py
verify: test lint typecheck schemas
cleanup:
	./scripts/p007 cleanup --run '$(RUN)' $(if $(CONFIRM),--confirm '$(CONFIRM)',)
