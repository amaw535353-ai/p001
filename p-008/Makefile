SHELL := /bin/bash
PY := .venv/bin/python
CLI := ./scripts/p008
DATASET ?= synthetic-core
VERSION ?= 1.0.0
SEED ?= 20261116
PROFILE ?= offline
SPLIT ?= all
FAMILY ?= authorization
.PHONY: doctor validate datasets dataset-build dataset-audit dataset-freeze plan eval report compare reproduce integrity-check benchmark-integrity import-p007 export demo test test-live lint typecheck schemas verify test-offline integrations cleanup
doctor:
	$(CLI) doctor
validate:
	./scripts/validate
datasets:
	$(CLI) datasets
dataset-build:
	$(CLI) dataset-build --dataset "$(DATASET)" --version "$(VERSION)" --seed "$(SEED)"
dataset-audit:
	$(CLI) dataset-audit --dataset "$(DATASET)" --version "$(VERSION)"
dataset-freeze:
	$(CLI) dataset-freeze --dataset "$(DATASET)" --version "$(VERSION)"
plan:
	$(CLI) plan --dataset "$(DATASET)" --version "$(VERSION)" --tool "$(PROFILE)" --split "$(SPLIT)"
eval:
	$(CLI) eval --dataset "$(DATASET)" --version "$(VERSION)" --tool "$(PROFILE)" --split "$(SPLIT)"
report:
	$(CLI) report --run "$(RUN)"
compare:
	$(CLI) compare --baseline "$(BASELINE)" --current "$(CURRENT)"
reproduce:
	$(CLI) reproduce --run "$(RUN)" $(if $(SAMPLE),--sample "$(SAMPLE)",)
integrity-check:
	$(CLI) integrity-check --dataset "$(DATASET)" --version "$(VERSION)" $(if $(RUN),--run "$(RUN)",)
benchmark-integrity:
	$(CLI) benchmark-integrity --run "$(RUN)"
import-p007:
	$(CLI) import-p007 --file "$(FILE)"
export:
	$(CLI) export --dataset "$(DATASET)" --version "$(VERSION)" $(if $(RUN),--run "$(RUN)",)
integrations:
	$(CLI) integrations
demo:
	$(CLI) demo
test:
	$(PY) -m pytest tests -m 'not live'
test-live:
	$(PY) -m pytest tests -m live
test-offline:
	PYTHONPATH=src/p008/adapters/offline_guard $(PY) -m pytest tests -m 'not live'
lint:
	.venv/bin/ruff check src tests scripts
	.venv/bin/ruff format --check src tests scripts
typecheck:
	.venv/bin/mypy src/p008
schemas:
	$(PY) scripts/build-schemas.py --check
verify: validate test lint typecheck schemas
cleanup:
	$(CLI) cleanup --run "$(RUN)" --confirm "$(CONFIRM)"
