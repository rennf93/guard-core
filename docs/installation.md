---

title: Installation - Guard Core
description: How to add guard-core as a dependency in your adapter library and set up a contributor development environment
keywords: guard-core, installation, adapter dependency, development setup, python security engine
---

Installation
============

guard-core is consumed as a **library dependency** by framework-specific adapters. This page covers two scenarios: depending on guard-core from your adapter's package, and setting up a local development environment to contribute to guard-core itself.

___

Add guard-core as an Adapter Dependency
----------------------------------------

In your adapter's `pyproject.toml`, add guard-core as a core dependency:

=== "pyproject.toml (PEP 621)"

    ```toml
    [project]
    name = "fastapi-guard"
    requires-python = ">=3.10"
    dependencies = [
        "guard-core>=1.0.0",
    ]
    ```

=== "pyproject.toml (Poetry)"

    ```toml
    [tool.poetry.dependencies]
    python = "^3.10"
    guard-core = "^1.0.0"
    ```

=== "setup.cfg"

    ```ini
    [options]
    install_requires =
        guard-core>=1.0.0
    python_requires = >=3.10
    ```

After adding the dependency, your adapter can import the public API:

```python
from guard_core import (
    SecurityConfig,
    GuardRequest,
    GuardResponse,
    GuardResponseFactory,
)
from guard_core.core.checks import SecurityCheckPipeline, SecurityCheck
from guard_core.core.events import SecurityEventBus, MetricsCollector
from guard_core.core.initialization import HandlerInitializer
from guard_core.core.responses import ErrorResponseFactory, ResponseContext
from guard_core.core.routing import RouteConfigResolver, RoutingContext
from guard_core.core.validation import RequestValidator, ValidationContext
from guard_core.core.bypass import BypassHandler, BypassContext
from guard_core.core.behavioral import BehavioralProcessor, BehavioralContext
```

### Optional Dependencies

guard-core has optional dependencies that your adapter may want to pull in:

| Dependency | Purpose | When Needed |
|---|---|---|
| `redis` | Distributed state (rate limits, bans, cloud IPs) | When `enable_redis=True` in `SecurityConfig` |
| `guard-agent` | Telemetry and monitoring SaaS integration | When `enable_agent=True` in `SecurityConfig` |
| `maxminddb` | GeoIP database reading | When using `IPInfoManager` for country filtering |
| `httpx` | Async HTTP client for cloud IP range fetching | When `block_cloud_providers` is configured |

___

Contributor Development Setup
-----------------------------

To work on guard-core itself:

### Prerequisites

- Python 3.10+ (3.10, 3.11, 3.12, 3.13 are all tested)
- [uv](https://docs.astral.sh/uv/) (modern Python package manager)
- Docker and Docker Compose (for containerized tests)
- Redis (for local integration tests)

### Clone and Install

```bash
git clone https://github.com/rennf93/guard-core.git
cd guard-core
make install-dev
```

This runs `uv sync --extra dev`, which installs all development dependencies including pytest, ruff, mypy, and pre-commit.

### Run Tests

```bash
make local-test
```

This executes `uv run pytest` with coverage reporting. A Redis instance must be running locally at `redis://localhost:6379` (or set the `REDIS_URL` environment variable).

To test across all supported Python versions using Docker:

```bash
make test-all
```

To test a specific Python version:

```bash
make test-3.12
```

### Code Quality

```bash
make fix
```

Runs `ruff format` and `ruff check --fix` across the codebase.

```bash
make lint
```

Runs ruff and mypy in Docker.

### Pre-commit Hooks

```bash
uv run pre-commit install
```

This installs hooks that run `ruff format`, `ruff check`, and `mypy` before every commit.

___

Project Layout
--------------

```text
guard-core/
├── guard_core/                 # Main package
│   ├── __init__.py            # Public API exports
│   ├── models.py              # SecurityConfig, DynamicRules
│   ├── utils.py               # Shared utilities
│   ├── protocols/             # Protocol definitions (the adapter contract)
│   │   ├── request_protocol.py
│   │   ├── response_protocol.py
│   │   ├── middleware_protocol.py
│   │   ├── geo_ip_protocol.py
│   │   ├── redis_protocol.py
│   │   └── agent_protocol.py
│   ├── core/                  # Modular engine internals
│   │   ├── checks/            # SecurityCheck base + 17 implementations + pipeline
│   │   ├── events/            # SecurityEventBus + MetricsCollector
│   │   ├── initialization/    # HandlerInitializer
│   │   ├── responses/         # ErrorResponseFactory + ResponseContext
│   │   ├── routing/           # RouteConfigResolver + RoutingContext
│   │   ├── validation/        # RequestValidator + ValidationContext
│   │   ├── bypass/            # BypassHandler + BypassContext
│   │   └── behavioral/        # BehavioralProcessor + BehavioralContext
│   ├── handlers/              # Singleton handlers (Redis, IP ban, rate limit, etc.)
│   ├── detection_engine/      # Attack pattern detection
│   └── decorators/            # Route-level security decorators
├── tests/                     # Test suite (100% coverage)
├── Makefile                   # Build automation
├── pyproject.toml             # Project metadata and tool config
└── uv.lock                   # Locked dependencies
```
