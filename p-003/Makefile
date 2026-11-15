SHELL := /bin/bash
.PHONY: setup test lint typecheck verify demo
setup:
	@./scripts/setup
test:
	@.venv/bin/python -m pytest tests
lint:
	@.venv/bin/ruff check src tests
	@.venv/bin/ruff format --check src tests
typecheck:
	@.venv/bin/mypy src/p003
verify:
	@./scripts/verify.sh
demo:
	@./scripts/p003 demo init --seed 42
