.PHONY: install install-dev test lint security-ci ci scan-leaky scan-clean rules help

PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
PY := $(VENV)/bin/python
PYTEST := $(VENV)/bin/pytest
RUFF := $(VENV)/bin/ruff
BANDIT := $(VENV)/bin/bandit
VS := $(VENV)/bin/vaultsweep

help:
	@echo "VaultSweep — BreachDirect / Stellar Wave 7"
	@echo ""
	@echo "  make install-dev  Create venv and install package"
	@echo "  make test         Run pytest"
	@echo "  make lint         Ruff check"
	@echo "  make security-ci  Bandit scan"
	@echo "  make ci           lint + test + security-ci"
	@echo "  make scan-leaky   Demo scan on leaky fixture"
	@echo "  make scan-clean   Demo scan on clean fixture"

install-dev:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install -e ".[dev]" 2>/dev/null || $(PIP) install -e . && $(PIP) install -r requirements-dev.txt

test:
	$(PYTEST) tests/ -v

lint:
	$(RUFF) check vaultsweep tests

security-ci:
	$(BANDIT) -r vaultsweep -ll -q

ci: lint test security-ci
	@echo "✅ make ci passed"

scan-leaky:
	$(VS) scan fixtures/leaky-repo --fail-on high || true

scan-clean:
	$(VS) scan fixtures/clean-repo

rules:
	$(VS) rules
