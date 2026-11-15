SHELL := /bin/bash
.PHONY: install doctor test demo-offline demo-diff verify schemas reset-owned
install:
	./scripts/setup
doctor:
	./scripts/p004 doctor
test:
	.venv/bin/python -m pytest tests
demo-offline:
	.venv/bin/python scripts/demo.py
demo-diff:
	.venv/bin/python scripts/demo.py --diff
schemas:
	.venv/bin/python scripts/build-schemas.py --check
verify:
	.venv/bin/python scripts/verify.py
reset-owned:
	@test -n "$(RUN)" || (echo 'Set RUN=reports/<owned-run>; evidence retained by default'; exit 2)
	./scripts/p004 reset-owned --input "$(RUN)" --confirm p004-local
