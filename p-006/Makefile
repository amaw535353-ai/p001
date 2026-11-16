SHELL := /bin/bash
PROFILE ?= hardened
CONFIRM ?=
export PYTHONPATH := $(CURDIR)/src
.PHONY: doctor validate up status down cleanup test test-identity test-authorization test-secrets test-gateway test-egress test-hardened test-weak compare evidence verify test-live lint typecheck
doctor validate status down:
	@./scripts/p006 $@
up:
	@./scripts/p006 up --profile '$(PROFILE)' --confirm '$(CONFIRM)'
cleanup:
	@./scripts/p006 cleanup --confirm '$(CONFIRM)'
test test-hardened:
	.venv/bin/python -m pytest tests -m 'not live'
test-identity:
	.venv/bin/python -m pytest tests -k identity
test-authorization:
	.venv/bin/python -m pytest tests -k policy
test-secrets:
	.venv/bin/python -m pytest tests -k vault
test-gateway:
	.venv/bin/python -m pytest tests -k gateway
test-egress:
	.venv/bin/python -m pytest tests -k network
test-weak:
	.venv/bin/python -m pytest tests -k weak
compare evidence verify:
	@./scripts/p006 $@
test-live:
	@./scripts/p006 live
compare-live:
	.venv/bin/python scripts/compare-live.py
lint:
	.venv/bin/ruff check src scripts tests
typecheck:
	.venv/bin/mypy src
