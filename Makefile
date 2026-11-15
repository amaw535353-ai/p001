SHELL := /bin/bash
.PHONY: doctor lab-up lab-test lab-evidence lab-down lab-rebuild-verify aws-plan unit static
doctor lab-up lab-test lab-evidence lab-down lab-rebuild-verify aws-plan:
	@./scripts/$@
unit:
	python3 -m unittest discover -s tests/unit -v
static:
	python3 scripts/static-check
