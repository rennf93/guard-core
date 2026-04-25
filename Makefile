PYTHON_VERSIONS = 3.10 3.11 3.12 3.13 3.14
DEFAULT_PYTHON = 3.10


.PHONY: sync
sync:
	@python scripts/unasync.py


.PHONY: check-sync
check-sync:
	@python scripts/unasync.py --check


.PHONY: install
install:
	@uv sync
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf


.PHONY: install-dev
install-dev:
	@uv sync --extra dev
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf


.PHONY: lock
lock:
	@uv lock
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf


.PHONY: upgrade
upgrade:
	@uv lock --upgrade
	@uv sync --all-extras
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf


.PHONY: stop
stop:
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f


.PHONY: restart
restart: stop


.PHONY: lint
lint:
	@echo 'Formatting w/ Ruff...'
	@echo ''
	@uv run ruff format .
	@echo ''
	@echo ''
	@echo 'Linting w/ Ruff...'
	@echo ''
	@uv run ruff check .
	@echo ''
	@echo 'Type checking w/ Mypy...'
	@echo ''
	@uv run mypy .
	@echo ''
	@echo ''
	@echo 'Finding dead code w/ Vulture...'
	@echo ''
	@uv run vulture
	@echo ''
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf


.PHONY: fix
fix:
	@echo "Fixing formatting w/ Ruff..."
	@echo ''
	@uv run ruff check --fix .
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf


.PHONY: vulture
vulture:
	@echo "Finding dead code with Vulture..."
	@echo ''
	@uv run vulture vulture_whitelist.py
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf


.PHONY: bandit
bandit:
	@echo "Running Bandit security scan..."
	@echo ''
	@uv run bandit -r guard_core -ll
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf


.PHONY: safety
safety:
	@echo "Checking dependencies with Safety..."
	@echo ''
	@uv run safety scan
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf


.PHONY: pip-audit
pip-audit:
	@echo "Auditing dependencies with pip-audit..."
	@echo ''
	@uv run pip-audit
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf


.PHONY: radon
radon:
	@echo "Analyzing code complexity with Radon..."
	@echo ''
	@echo "Cyclomatic Complexity:"
	@uv run radon cc guard_core -nc
	@echo ''
	@echo "Maintainability Index:"
	@uv run radon mi guard_core -nc
	@echo ''
	@echo "Raw Metrics:"
	@uv run radon raw guard_core
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf


.PHONY: xenon
xenon:
	@echo "Checking complexity thresholds with Xenon..."
	@echo ''
	@uv run xenon guard_core --max-absolute B --max-modules A --max-average A
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf


.PHONY: deptry
deptry:
	@echo "Analyzing dependencies with Deptry..."
	@echo ''
	@uv run deptry .
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf


.PHONY: semgrep
semgrep:
	@echo "Running Semgrep static analysis..."
	@echo ''
	@uv run semgrep --config=auto guard_core
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf


.PHONY: security
security: bandit safety pip-audit
	@echo "All security checks completed."


.PHONY: quality
quality: lint vulture radon xenon
	@echo "All code quality checks completed."


.PHONY: analysis
analysis: deptry semgrep
	@echo "All analysis tools completed."


.PHONY: check-all
check-all: lint security quality analysis
	@echo "All checks completed."


.PHONY: test
test:
	@COMPOSE_BAKE=true PYTHON_VERSION=$(DEFAULT_PYTHON) docker compose run --rm --build guard-core pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f


.PHONY: test-all
test-all: test-3.10 test-3.11 test-3.12 test-3.13 test-3.14


.PHONY: test-3.10
test-3.10:
	@docker compose down -v guard-core
	@COMPOSE_BAKE=true PYTHON_VERSION=3.10 docker compose build guard-core
	@PYTHON_VERSION=3.10 docker compose run --rm guard-core pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f


.PHONY: test-3.11
test-3.11:
	@docker compose down -v guard-core
	@COMPOSE_BAKE=true PYTHON_VERSION=3.11 docker compose build guard-core
	@PYTHON_VERSION=3.11 docker compose run --rm guard-core pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f


.PHONY: test-3.12
test-3.12:
	@docker compose down -v guard-core
	@COMPOSE_BAKE=true PYTHON_VERSION=3.12 docker compose build guard-core
	@PYTHON_VERSION=3.12 docker compose run --rm guard-core pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f


.PHONY: test-3.13
test-3.13:
	@docker compose down -v guard-core
	@COMPOSE_BAKE=true PYTHON_VERSION=3.13 docker compose build guard-core
	@PYTHON_VERSION=3.13 docker compose run --rm guard-core pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f


.PHONY: test-3.14
test-3.14:
	@docker compose down -v guard-core
	@COMPOSE_BAKE=true PYTHON_VERSION=3.14 docker compose build guard-core
	@PYTHON_VERSION=3.14 docker compose run --rm guard-core pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f


.PHONY: local-test
local-test:
	@REDIS_URL=redis://localhost:6379 uv run pytest -v --cov=guard_core --cov-report=term-missing
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf


.PHONY: integration-test
integration-test:
	@INTEGRATION_TESTS=1 REDIS_URL=$${REDIS_URL:-redis://localhost:6379} IPINFO_TOKEN=$${IPINFO_TOKEN:-test_token} REDIS_PREFIX=$${REDIS_PREFIX:-test:guard_core:} uv run pytest tests/integration -m integration -v
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf


.PHONY: serve-docs
serve-docs:
	@uv run mkdocs serve
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf


.PHONY: lint-docs
lint-docs:
	@uv run pymarkdownlnt scan -r --respect-gitignore -e ./.venv -e ./.git -e ./.github -e ./data -e ./guard_core -e ./tests -e ./.claude -e ./CLAUDE.md -e ./.cursor -e ./.kiro -e ./ZZZ .
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf


.PHONY: fix-docs
fix-docs:
	@uv run pymarkdownlnt fix -r --respect-gitignore -e ./.venv -e ./.git -e ./.github -e ./data -e ./guard_core -e ./tests -e ./.claude -e ./CLAUDE.md -e ./.cursor -e ./.kiro -e ./ZZZ .
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf


.PHONY: prune
prune:
	@docker system prune -f


.PHONY: clean
clean:
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf


.PHONY: bump-version
bump-version:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make bump-version VERSION=x.y.z"; exit 1; fi
	@uv run python .github/scripts/bump_version.py $(VERSION)


.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'


.DEFAULT_GOAL := help


.PHONY: show-python-versions
show-python-versions:
	@echo "Supported Python versions: $(PYTHON_VERSIONS)"
	@echo "Default Python version: $(DEFAULT_PYTHON)"
