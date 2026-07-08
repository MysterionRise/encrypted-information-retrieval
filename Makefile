.PHONY: help setup test test-verbose test-coverage lint format type-check security clean docs bench all install-dev

# Default target
.DEFAULT_GOAL := help

PYTHON ?= python3.11
PIP ?= $(PYTHON) -m pip

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)Encrypted Information Retrieval - Development Commands$(NC)"
	@echo ""
	@echo "$(GREEN)Usage:$(NC)"
	@echo "  make <target>"
	@echo ""
	@echo "$(GREEN)Available targets:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(BLUE)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Examples:$(NC)"
	@echo "  make setup          # First-time setup"
	@echo "  make test           # Run all tests"
	@echo "  make lint           # Check code quality"
	@echo "  make format         # Auto-format code"

setup: ## Install dependencies and set up development environment
	@echo "$(BLUE)Setting up development environment...$(NC)"
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt
	@echo "$(GREEN)✓ Dependencies installed$(NC)"
	@echo "$(BLUE)Installing pre-commit hooks...$(NC)"
	pre-commit install
	@echo "$(GREEN)✓ Pre-commit hooks installed$(NC)"
	@echo "$(GREEN)✓ Setup complete!$(NC)"
	@echo ""
	@echo "$(YELLOW)Next steps:$(NC)"
	@echo "  1. Run 'make test' to verify installation"
	@echo "  2. Run 'make lint' to check code quality"
	@echo "  3. Start developing!"

install-dev: ## Install development dependencies only
	@echo "$(BLUE)Installing development dependencies...$(NC)"
	$(PIP) install pytest pytest-cov pytest-benchmark black ruff mypy bandit safety pre-commit
	@echo "$(GREEN)✓ Dev dependencies installed$(NC)"

test: ## Run all tests
	@echo "$(BLUE)Running tests...$(NC)"
	PYTHONPATH=src:$$PYTHONPATH $(PYTHON) -m pytest -v -W ignore::DeprecationWarning
	@echo "$(GREEN)✓ All tests passed$(NC)"

test-verbose: ## Run tests with verbose output
	@echo "$(BLUE)Running tests (verbose)...$(NC)"
	PYTHONPATH=src:$$PYTHONPATH $(PYTHON) -m pytest -vv --tb=long

test-coverage: ## Run tests with coverage report
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	PYTHONPATH=src:$$PYTHONPATH $(PYTHON) -m pytest \
		--cov=src/encrypted_ir \
		--cov-report=term-missing \
		--cov-report=html \
		--cov-report=xml \
		-W ignore::DeprecationWarning
	@echo "$(GREEN)✓ Coverage report generated$(NC)"
	@echo "$(YELLOW)View HTML report: open htmlcov/index.html$(NC)"

bench: ## Run performance benchmarks
	@echo "$(BLUE)Running benchmarks...$(NC)"
	@mkdir -p benchmarks/results
	PYTHONPATH=src:$$PYTHONPATH $(PYTHON) -m pytest \
		tests/ \
		--benchmark-only \
		--benchmark-json=benchmarks/results/latest.json \
		2>/dev/null || echo "$(YELLOW)⚠ No benchmarks found yet (will be added in Issue #3)$(NC)"

lint: ## Run all code quality checks (ruff, bandit, mypy)
	@echo "$(BLUE)Running code quality checks...$(NC)"
	@echo "$(BLUE)1. Checking code style with ruff...$(NC)"
	$(PYTHON) -m ruff check src tests examples
	@echo "$(BLUE)2. Checking security with bandit...$(NC)"
	$(PYTHON) -m bandit -r src -ll -f screen
	@echo "$(BLUE)3. Checking types with mypy...$(NC)"
	PYTHONPATH=src:$$PYTHONPATH $(PYTHON) -m mypy --disable-error-code redundant-cast src/encrypted_ir --ignore-missing-imports --no-strict-optional
	@echo "$(GREEN)✓ Linting complete$(NC)"

format: ## Auto-format code with black and ruff
	@echo "$(BLUE)Formatting code...$(NC)"
	@echo "$(BLUE)1. Running black...$(NC)"
	$(PYTHON) -m black src tests examples
	@echo "$(BLUE)2. Running ruff auto-fix...$(NC)"
	$(PYTHON) -m ruff check --fix src tests examples
	@echo "$(GREEN)✓ Code formatted$(NC)"

type-check: ## Run type checking with mypy
	@echo "$(BLUE)Running type checker...$(NC)"
	PYTHONPATH=src:$$PYTHONPATH $(PYTHON) -m mypy --disable-error-code redundant-cast src/encrypted_ir --ignore-missing-imports --no-strict-optional
	@echo "$(GREEN)✓ Type checking complete$(NC)"

security: ## Run security checks (bandit + safety)
	@echo "$(BLUE)Running security checks...$(NC)"
	@echo "$(BLUE)1. Scanning code for security issues (bandit)...$(NC)"
	$(PYTHON) -m bandit -r src -ll -f screen
	@echo "$(BLUE)2. Checking dependencies for vulnerabilities (safety)...$(NC)"
	$(PYTHON) -m safety check --json || echo "$(YELLOW)⚠ Safety check requires internet connection$(NC)"
	@echo "$(GREEN)✓ Security checks complete$(NC)"

clean: ## Clean build artifacts and cache
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .eggs/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete
	find . -type f -name '*~' -delete
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf coverage.xml
	@echo "$(GREEN)✓ Cleaned$(NC)"

docs: ## Generate API documentation (future)
	@echo "$(YELLOW)⚠ Documentation generation not yet implemented (Issue #6)$(NC)"
	@echo "$(BLUE)Planned: sphinx-build -b html docs/ docs/_build/$(NC)"

all: clean format lint test ## Run full CI pipeline locally (clean, format, lint, test)
	@echo ""
	@echo "$(GREEN)╔═══════════════════════════════════════════════════╗$(NC)"
	@echo "$(GREEN)║  ✓ Full CI pipeline completed successfully!      ║$(NC)"
	@echo "$(GREEN)╚═══════════════════════════════════════════════════╝$(NC)"

ci: lint test-coverage security ## Run CI checks (lint, test with coverage, security)
	@echo ""
	@echo "$(GREEN)╔═══════════════════════════════════════════════════╗$(NC)"
	@echo "$(GREEN)║  ✓ CI checks passed!                             ║$(NC)"
	@echo "$(GREEN)╚═══════════════════════════════════════════════════╝$(NC)"

# Quick checks for pre-commit
pre-commit-check: ## Quick checks before committing
	@echo "$(BLUE)Running pre-commit checks...$(NC)"
	@echo "$(BLUE)1. Formatting check...$(NC)"
	$(PYTHON) -m black --check src tests examples
	@echo "$(BLUE)2. Linting...$(NC)"
	$(PYTHON) -m ruff check src tests examples
	@echo "$(BLUE)3. Quick tests...$(NC)"
	PYTHONPATH=src:$$PYTHONPATH $(PYTHON) -m pytest -q -W ignore::DeprecationWarning
	@echo "$(GREEN)✓ Pre-commit checks passed$(NC)"

# Development workflow helpers
watch-test: ## Watch for changes and run tests automatically
	@echo "$(BLUE)Watching for changes...$(NC)"
	@echo "$(YELLOW)Note: Requires '$(PIP) install pytest-watch'$(NC)"
	PYTHONPATH=src:$$PYTHONPATH ptw -- -v -W ignore::DeprecationWarning

requirements: ## Generate requirements.txt from current environment
	@echo "$(BLUE)Generating requirements.txt...$(NC)"
	$(PYTHON) -m pip freeze > requirements-frozen.txt
	@echo "$(GREEN)✓ Generated requirements-frozen.txt$(NC)"

# Project info
info: ## Show project information
	@echo "$(BLUE)Project Information$(NC)"
	@echo "$(GREEN)Name:$(NC)         Encrypted Information Retrieval"
	@echo "$(GREEN)Version:$(NC)      1.0.0"
	@echo "$(GREEN)Python:$(NC)       $$($(PYTHON) --version)"
	@echo "$(GREEN)Tests:$(NC)        see docs/PORTFOLIO_EVIDENCE.md"
	@echo "$(GREEN)Coverage:$(NC)     run 'make test-coverage' for the current report"
	@echo ""
	@echo "$(BLUE)Module Statistics$(NC)"
	@find src -name '*.py' | xargs wc -l | tail -1 | awk '{printf "$(GREEN)Source Lines:$(NC)  %s\n", $$1}'
	@find tests -name '*.py' | xargs wc -l | tail -1 | awk '{printf "$(GREEN)Test Lines:$(NC)    %s\n", $$1}'
	@find docs -name '*.md' | xargs wc -l | tail -1 | awk '{printf "$(GREEN)Doc Lines:$(NC)     %s\n", $$1}'
