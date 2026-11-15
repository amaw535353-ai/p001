SHELL := /bin/bash
ID ?= S01
.PHONY: doctor generate validate test scenario-list scenario-seed scenario-reset export integration-test evidence down lint typecheck

doctor generate validate export evidence:
	@./scripts/p002 $@
test:
	@PYTHONPATH=src .venv/bin/python -m pytest tests
lint:
	@.venv/bin/ruff check src tests
	@.venv/bin/ruff format --check src tests
typecheck:
	@PYTHONPATH=src .venv/bin/mypy src/p002
scenario-list:
	@./scripts/p002 scenarios list
scenario-seed:
	@./scripts/p002 scenarios seed $(ID) $(if $(UNSAFE),--unsafe-scenario,)
scenario-reset:
	@./scripts/p002 scenarios reset $(ID)
integration-test:
	@./scripts/integration-test
down:
	@./scripts/p002 down --confirm p002-local
