<p align="center">
    <a href="https://rennf93.github.io/guard-core/latest/">
        <img src="https://rennf93.github.io/guard-core/latest/assets/big_logo.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>guard-core is the framework-agnostic security engine that powers the Guard ecosystem. It provides IP control, rate limiting, penetration detection, security headers, and behavioral analysis through a protocol-based architecture. Framework-specific adapters (fastapi-guard, flaskapi-guard, djapi-guard) consume this library.</strong>
</p>

<p align="center">
    <a href="https://badge.fury.io/py/guard-core">
        <img src="https://badge.fury.io/py/guard-core.svg?cache=none&icon=si%3Apython&icon_color=%23008cb4" alt="PyPiVersion">
    </a>
    <a href="https://github.com/rennf93/guard-core/actions/workflows/release.yml">
        <img src="https://github.com/rennf93/guard-core/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/rennf93/guard-core/actions/workflows/ci.yml">
        <img src="https://github.com/rennf93/guard-core/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/rennf93/guard-core/actions/workflows/code-ql.yml">
        <img src="https://github.com/rennf93/guard-core/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/rennf93/guard-core/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/rennf93/guard-core/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/rennf93/guard-core/actions/workflows/docs.yml">
        <img src="https://github.com/rennf93/guard-core/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/rennf93/guard-core?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/Python-3776AB.svg?style=flat&amp;logo=Python&amp;logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/Redis-FF4438.svg?style=flat&amp;logo=Redis&amp;logoColor=white" alt="Redis">
    <a href="https://pepy.tech/project/guard-core">
        <img src="https://pepy.tech/badge/guard-core" alt="Downloads">
    </a>
</p>

___

Documentation
=============

📚 **[Documentation](https://rennf93.github.io/guard-core)** - Full technical documentation for adapter developers.

🤖 **[Monitoring Agent Integration](https://github.com/rennf93/fastapi-guard-agent)** - Monitor your Guard instance with a monitoring agent.

___

Ecosystem
---------

Guard Core is the engine. Framework adapters are thin wrappers that translate native request/response types into Guard Core's protocols:

```text
guard-core (this library)
├── fastapi-guard      ← ASGI adapter for FastAPI/Starlette
├── flaskapi-guard     ← WSGI adapter for Flask
└── djapi-guard        ← Django middleware adapter
```

Adapter developers implement three protocols — `GuardRequest`, `GuardResponse`, and `GuardResponseFactory` — to bridge their framework into the security pipeline. Everything else (17 security checks, detection engine, Redis state, event telemetry) works out of the box.

___

Features
--------

- **IP Whitelisting and Blacklisting**: Control access based on IP addresses and CIDR ranges.
- **User Agent Filtering**: Block requests from specific user agents.
- **Rate Limiting**: Sliding window algorithm with in-memory and Redis-backed storage.
- **Automatic IP Banning**: Threshold-based banning with configurable duration.
- **Penetration Attempt Detection**: SQL injection, XSS, command injection, path traversal detection with semantic analysis.
- **HTTP Security Headers**: CSP, HSTS, X-Frame-Options, and OWASP best practices.
- **Cloud Provider IP Blocking**: Block requests from AWS, GCP, Azure IP ranges.
- **IP Geolocation**: Country-based access control via GeoIP databases.
- **Behavioral Analysis**: Usage monitoring, return pattern detection, frequency analysis.
- **Security Decorators**: Route-level security with composable decorator mixins.
- **Detection Engine**: Multi-layered threat detection with regex, semantic analysis, and performance monitoring.
- **Distributed State Management**: Redis integration for shared state across instances.
- **Protocol-Based Architecture**: Framework-agnostic via `GuardRequest`/`GuardResponse` protocols.

___

Installation
------------

```bash
pip install guard-core
```

___

For Adapter Developers
----------------------

If you're building a framework adapter, add guard-core as a dependency:

```toml
[project]
dependencies = [
    "guard-core",
]
```

Then implement the three protocols:

```python
from guard_core.protocols import GuardRequest, GuardResponse, GuardResponseFactory

class MyFrameworkRequest:
    """Wraps your framework's request into GuardRequest protocol."""

    def __init__(self, native_request):
        self._request = native_request

    @property
    def url_path(self) -> str:
        return self._request.path

    @property
    def method(self) -> str:
        return self._request.method

    @property
    def client_host(self) -> str | None:
        return self._request.remote_addr

    @property
    def headers(self):
        return dict(self._request.headers)

    # ... implement remaining protocol properties
```

See the [Building Adapters Guide](https://rennf93.github.io/guard-core/latest/adapters/getting-started/) for the complete walkthrough.

___

Security Pipeline
-----------------

Guard Core executes 17 security checks in order for every request:

1. Route configuration extraction
2. Emergency mode
3. HTTPS enforcement
4. Request logging
5. Size/content validation
6. Required headers
7. Authentication
8. Referrer validation
9. Custom validators
10. Time windows
11. Cloud IP refresh
12. IP security (whitelist/blacklist)
13. Cloud provider blocking
14. User agent filtering
15. Rate limiting
16. Suspicious activity detection
17. Custom request checks

Each check returns `None` (pass) or a `GuardResponse` (block). The pipeline short-circuits on the first blocking response.

___

SecurityConfig
--------------

All behavior is controlled through `SecurityConfig`:

```python
from guard_core.models import SecurityConfig

config = SecurityConfig(
    whitelist=["192.168.1.0/24"],
    blacklist=["10.0.0.1"],
    blocked_countries=["CN"],
    blocked_user_agents=["curl", "wget"],
    auto_ban_threshold=5,
    auto_ban_duration=86400,
    rate_limit=100,
    rate_limit_window=60,
    enforce_https=True,
    block_cloud_providers={"AWS", "GCP", "Azure"},
    enable_redis=True,
    redis_url="redis://localhost:6379",
)
```

See the [SecurityConfig Reference](https://rennf93.github.io/guard-core/latest/configuration/security-config/) for all fields.

___

Detection Engine
----------------

Multi-layered threat detection:

- **PatternCompiler**: ReDoS-safe regex compilation with LRU caching and timeout protection.
- **ContentPreprocessor**: Unicode normalization, encoding detection, attack-region-aware truncation.
- **SemanticAnalyzer**: Attack probability scoring, entropy analysis, obfuscation detection.
- **PerformanceMonitor**: Anomaly detection, slow pattern tracking, statistical analysis.

See the [Detection Engine Internals](https://rennf93.github.io/guard-core/latest/internals/detection-engine/) for details.

___

Redis Integration
-----------------

Distributed state management across multiple instances:

```python
config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://prod-redis:6379/1",
    redis_prefix="myapp:security:",
)
```

Provides atomic rate limiting, distributed IP ban tracking, cloud IP range caching, and pattern storage.

___

Development
-----------

```bash
# Clone and install
git clone https://github.com/rennf93/guard-core.git
cd guard-core
make install-dev

# Run tests (100% coverage)
make local-test

# Run all quality checks
make check-all

# Serve documentation
make serve-docs
```

___

Contributing
------------

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

___

License
-------

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

___

Author
------

Renzo Franceschini - [rennf93@users.noreply.github.com](mailto:rennf93@users.noreply.github.com)

___

Acknowledgements
----------------

- [Pydantic](https://docs.pydantic.dev/)
- [Redis](https://redis.io/)
- [httpx](https://www.python-httpx.org/)
- [cachetools](https://cachetools.readthedocs.io/)
- [MaxMind DB](https://maxmind.github.io/MaxMind-DB/)
