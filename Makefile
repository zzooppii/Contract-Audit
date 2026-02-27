.PHONY: install test lint fmt audit clean build docker help

PYTHON := python3
PIP := pip
PYTEST := pytest
RUFF := ruff
CONTRACT_AUDIT := contract-audit

## help: Show this help message
help:
	@echo "contract-audit Makefile targets:"
	@grep -E '^## [a-z]' Makefile | sed 's/## /  /'

## install: Install all dependencies (development)
install:
	$(PIP) install hatch
	hatch env create
	$(PIP) install -e ".[dev]"
	@echo "✓ Dependencies installed"

## test: Run all tests
test:
	$(PYTEST) tests/ -v --tb=short

## test-unit: Run only unit tests
test-unit:
	$(PYTEST) tests/unit/ -v

## test-integration: Run integration tests
test-integration:
	$(PYTEST) tests/integration/ -v

## test-e2e: Run end-to-end tests
test-e2e:
	$(PYTEST) tests/e2e/ -v

## test-cov: Run tests with coverage report
test-cov:
	$(PYTEST) tests/ -v --cov=src/contract_audit --cov-report=html --cov-report=term

## lint: Run ruff linting
lint:
	$(RUFF) check src/ tests/

## fmt: Format code with ruff
fmt:
	$(RUFF) format src/ tests/

## audit: Run audit on this project's own test contracts
audit:
	$(CONTRACT_AUDIT) audit tests/fixtures/contracts \
		--config config/default.toml \
		--output audit-results \
		--no-llm

## audit-full: Run full audit with LLM (requires API keys)
audit-full:
	$(CONTRACT_AUDIT) audit tests/fixtures/contracts \
		--config config/default.toml \
		--output audit-results \
		--formats sarif,json,markdown,html

## login-anthropic: Authenticate with Anthropic OAuth
login-anthropic:
	$(CONTRACT_AUDIT) login --anthropic

## login-google: Authenticate with Google OAuth
login-google:
	$(CONTRACT_AUDIT) login --google

## clean: Remove build artifacts and cache
clean:
	rm -rf .coverage htmlcov/ dist/ build/ *.egg-info/
	rm -rf audit-results/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete

## build: Build distribution packages
build:
	hatch build

## docker-build: Build Docker image
docker-build:
	docker build --target production -t contract-audit:latest .

## docker-dev: Start development container
docker-dev:
	docker build --target development -t contract-audit:dev .
	docker run -it --rm \
		-v $$(pwd):/app \
		-e ANTHROPIC_API_KEY \
		-e GOOGLE_AI_API_KEY \
		contract-audit:dev

## server: Start the web API server
server:
	uvicorn contract_audit.api.app:app --reload --host 0.0.0.0 --port 8000

## version: Show tool versions
version:
	$(CONTRACT_AUDIT) version

## init: Initialize config in current directory
init:
	$(CONTRACT_AUDIT) init
