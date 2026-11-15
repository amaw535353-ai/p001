SHELL := /bin/bash
.PHONY: install doctor test verify demo-offline demo-integrations schemas
install:
	./scripts/setup
doctor:
	./scripts/p005 doctor
test:
	.venv/bin/python -m pytest tests --basetemp=evidence/pytest
verify:
	.venv/bin/python scripts/verify.py
demo-offline:
	PYTHONPATH=tests/no-network .venv/bin/python scripts/demo.py
demo-integrations:
	PYTHONPATH=tests/no-network .venv/bin/python scripts/demo-integrations.py
schemas:
	.venv/bin/python scripts/build-schemas.py --check
