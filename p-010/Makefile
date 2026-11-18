SHELL := /bin/bash
PY := .venv/bin/python
CLI := ./scripts/p010
OFFLINE := PYTHONPATH=tests/offline_guard:src
CONFIRM ?=
.PHONY: setup doctor validate lint typecheck verify test test-offline demo redmine-up cleanup
setup:
	./scripts/setup
doctor:
	$(CLI) doctor
validate:
	PYTHONPATH=src $(PY) scripts/build-schemas.py --check
lint:
	.venv/bin/ruff check src tests scripts
	.venv/bin/ruff format --check src tests scripts
typecheck:
	.venv/bin/mypy src/p010
test:
	PYTHONPATH=src $(PY) -m pytest
test-offline:
	$(OFFLINE) $(PY) -m pytest
demo:
	$(OFFLINE) $(CLI) demo
verify: validate lint typecheck test-offline
redmine-up:
	$(CLI) redmine up
cleanup:
	$(CLI) redmine down --confirm "$(CONFIRM)"
