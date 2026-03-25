---

title: Testing Adapters
description: How to test guard-core adapters using mock objects, check-level unit tests, wrapper verification, and integration testing patterns.
keywords: guard-core, testing, MockGuardRequest, MockGuardResponse, adapter testing, security checks, integration tests
---

Testing Adapters
================

Mock Objects from guard-core
----------------------------

Guard-core ships mock implementations of both protocols in `tests/conftest.py`. Use them as references for your own test fixtures, or import them directly in your adapter's test suite.

### MockState

A mutable namespace that mimics `request.state`:

```python
class MockState:
    def __init__(self) -> None:
        self._attrs: dict = {}

    def __getattr__(self, name: str) -> object:
        if name == "_attrs":
            return super().__getattribute__(name)
        return self._attrs.get(name)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "_attrs":
            super().__setattr__(name, value)
        else:
            self._attrs[name] = value
```

### MockGuardRequest

A complete `GuardRequest` implementation for testing:

```python
class MockGuardRequest:
    def __init__(
        self,
        path: str = "/",
        method: str = "GET",
        headers: dict | None = None,
        client_host: str | None = "127.0.0.1",
        scheme: str = "https",
        query_params: dict | None = None,
        body_content: bytes = b"",
        scope: dict | None = None,
    ) -> None:
        self._path = path
        self._method = method
        self._headers = headers or {}
        self._client_host = client_host
        self._scheme = scheme
        self._query_params = query_params or {}
        self._body = body_content
        self._state = MockState()
        self._scope = scope or {}

    @property
    def url_path(self) -> str:
        return self._path

    @property
    def url_scheme(self) -> str:
        return self._scheme

    @property
    def url_full(self) -> str:
        return f"{self._scheme}://test{self._path}"

    def url_replace_scheme(self, scheme: str) -> str:
        return f"{scheme}://test{self._path}"

    @property
    def method(self) -> str:
        return self._method

    @property
    def client_host(self) -> str | None:
        return self._client_host

    @property
    def headers(self) -> dict:
        return self._headers

    @property
    def query_params(self) -> dict:
        return self._query_params

    async def body(self) -> bytes:
        return self._body

    @property
    def state(self) -> MockState:
        return self._state

    @property
    def scope(self) -> dict:
        return self._scope
```

### MockGuardResponse

```python
class MockGuardResponse:
    def __init__(
        self,
        content: str = "",
        status_code: int = 200,
        headers: dict | None = None,
    ) -> None:
        self._status_code = status_code
        self._headers = headers or {}
        self._body = content.encode() if isinstance(content, str) else content

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def headers(self) -> dict:
        return self._headers

    @property
    def body(self) -> bytes:
        return self._body
```

### MockGuardResponseFactory

```python
class MockGuardResponseFactory:
    def create_response(self, content: str, status_code: int) -> MockGuardResponse:
        return MockGuardResponse(content, status_code)

    def create_redirect_response(
        self, url: str, status_code: int
    ) -> MockGuardResponse:
        return MockGuardResponse(
            f"Redirect to {url}", status_code, {"Location": url}
        )
```

### Pytest Fixtures

Guard-core's `conftest.py` provides ready-made fixtures:

```python
@pytest.fixture
def mock_request() -> MockGuardRequest:
    return MockGuardRequest()

@pytest.fixture
def mock_response() -> MockGuardResponse:
    return MockGuardResponse()

@pytest.fixture
def mock_response_factory() -> MockGuardResponseFactory:
    return MockGuardResponseFactory()

@pytest.fixture
def security_config() -> SecurityConfig:
    return SecurityConfig(enable_redis=False)
```

And singleton cleanup fixtures that run automatically:

```python
@pytest.fixture(autouse=True)
def cleanup_ipban_singleton() -> None:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None

@pytest.fixture(autouse=True)
def cleanup_suspatterns_singleton() -> None:
    SusPatternsManager._instance = None
    yield
    SusPatternsManager._instance = None

@pytest.fixture(autouse=True)
def reset_headers_manager() -> None:
    SecurityHeadersManager._instance = None
    yield
    SecurityHeadersManager._instance = None
```

These cleanup fixtures are critical. `IPBanManager`, `SusPatternsManager`, and `SecurityHeadersManager` are singletons. Without resetting them between tests, state leaks across test cases.

Testing Individual Security Checks
----------------------------------

Each security check can be tested in isolation by creating a mock middleware object and passing it to the check:

```python
import pytest
from unittest.mock import AsyncMock, MagicMock

from guard_core.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.models import SecurityConfig


class MockMiddleware:
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self.logger = MagicMock()
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts: dict[str, int] = {}
        self.event_bus = MagicMock()
        self.event_bus.send_middleware_event = AsyncMock()
        self.route_resolver = MagicMock()
        self.response_factory = MagicMock()
        self.rate_limit_handler = MagicMock()
        self.agent_handler = None
        self.geo_ip_handler = None
        self.guard_response_factory = MockGuardResponseFactory()

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> MockGuardResponse:
        return MockGuardResponse(default_message, status_code)

    async def refresh_cloud_ip_ranges(self) -> None:
        pass


@pytest.mark.asyncio
async def test_ip_blacklist_blocks():
    config = SecurityConfig(
        enable_redis=False,
        blacklist=["192.168.1.100"],
    )
    middleware = MockMiddleware(config)
    check = IpSecurityCheck(middleware)

    request = MockGuardRequest(client_host="192.168.1.100")
    request.state._guard_client_ip = "192.168.1.100"
    request.state._guard_route_config = None

    response = await check.check(request)
    assert response is not None
    assert response.status_code == 403
```

Testing Your Adapter's Request Wrapper
--------------------------------------

Verify that your wrapper correctly implements every `GuardRequest` property:

```python
import pytest
from starlette.testclient import TestClient
from starlette.requests import Request
from starlette.routing import Route

from your_guard.request import StarletteGuardRequest
from guard_core.protocols.request_protocol import GuardRequest


def test_protocol_conformance():
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "query_string": b"key=value",
        "headers": [(b"host", b"example.com"), (b"user-agent", b"test")],
        "server": ("example.com", 443),
        "scheme": "https",
    }
    request = Request(scope)
    wrapped = StarletteGuardRequest(request)

    assert isinstance(wrapped, GuardRequest)


def test_url_path():
    scope = {"type": "http", "method": "GET", "path": "/api/users"}
    request = Request(scope)
    wrapped = StarletteGuardRequest(request)

    assert wrapped.url_path == "/api/users"


def test_url_scheme():
    scope = {"type": "http", "method": "GET", "path": "/", "scheme": "https"}
    request = Request(scope)
    wrapped = StarletteGuardRequest(request)

    assert wrapped.url_scheme == "https"


def test_method():
    scope = {"type": "http", "method": "POST", "path": "/"}
    request = Request(scope)
    wrapped = StarletteGuardRequest(request)

    assert wrapped.method == "POST"


def test_client_host():
    scope = {"type": "http", "method": "GET", "path": "/", "client": ("10.0.0.1", 8080)}
    request = Request(scope)
    wrapped = StarletteGuardRequest(request)

    assert wrapped.client_host == "10.0.0.1"


def test_client_host_none():
    scope = {"type": "http", "method": "GET", "path": "/"}
    request = Request(scope)
    wrapped = StarletteGuardRequest(request)

    assert wrapped.client_host is None


def test_headers():
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-custom", b"value")],
    }
    request = Request(scope)
    wrapped = StarletteGuardRequest(request)

    assert wrapped.headers.get("x-custom") == "value"


@pytest.mark.asyncio
async def test_body():
    async def receive():
        return {"type": "http.request", "body": b"test body"}

    scope = {"type": "http", "method": "POST", "path": "/"}
    request = Request(scope, receive)
    wrapped = StarletteGuardRequest(request)

    assert await wrapped.body() == b"test body"


def test_state_is_mutable():
    scope = {"type": "http", "method": "GET", "path": "/"}
    request = Request(scope)
    wrapped = StarletteGuardRequest(request)

    wrapped.state.custom_value = "test"
    assert wrapped.state.custom_value == "test"


def test_url_replace_scheme():
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "scheme": "http",
        "server": ("example.com", 80),
    }
    request = Request(scope)
    wrapped = StarletteGuardRequest(request)

    replaced = wrapped.url_replace_scheme("https")
    assert replaced.startswith("https://")
```

Testing Your Response Wrapper
-----------------------------

```python
from your_guard.response import StarletteGuardResponse, StarletteResponseFactory
from guard_core.protocols.response_protocol import GuardResponse, GuardResponseFactory


def test_response_protocol_conformance():
    factory = StarletteResponseFactory()
    response = factory.create_response("Forbidden", 403)
    assert isinstance(response, GuardResponse)


def test_response_factory_protocol_conformance():
    factory = StarletteResponseFactory()
    assert isinstance(factory, GuardResponseFactory)


def test_create_response():
    factory = StarletteResponseFactory()
    response = factory.create_response("Not Found", 404)

    assert response.status_code == 404


def test_headers_are_mutable():
    factory = StarletteResponseFactory()
    response = factory.create_response("OK", 200)

    response.headers["X-Custom"] = "test"
    assert response.headers["X-Custom"] == "test"


def test_create_redirect():
    factory = StarletteResponseFactory()
    response = factory.create_redirect_response("https://example.com", 301)

    assert response.status_code == 301
    assert response.headers["Location"] == "https://example.com"
```

Testing the Pipeline
--------------------

Test the full security pipeline using mock objects:

```python
import pytest
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.checks.base import SecurityCheck


class AlwaysPassCheck(SecurityCheck):
    check_name = "always_pass"

    async def check(self, request):
        return None


class AlwaysBlockCheck(SecurityCheck):
    check_name = "always_block"

    async def check(self, request):
        return await self.create_error_response(403, "Blocked")


@pytest.mark.asyncio
async def test_pipeline_passes_when_all_checks_pass():
    middleware = MockMiddleware(SecurityConfig(enable_redis=False))
    pipeline = SecurityCheckPipeline([
        AlwaysPassCheck(middleware),
        AlwaysPassCheck(middleware),
    ])

    request = MockGuardRequest()
    result = await pipeline.execute(request)
    assert result is None


@pytest.mark.asyncio
async def test_pipeline_blocks_on_first_failure():
    middleware = MockMiddleware(SecurityConfig(enable_redis=False))
    pipeline = SecurityCheckPipeline([
        AlwaysPassCheck(middleware),
        AlwaysBlockCheck(middleware),
        AlwaysPassCheck(middleware),
    ])

    request = MockGuardRequest()
    result = await pipeline.execute(request)
    assert result is not None
    assert result.status_code == 403
```

Integration Testing Patterns
----------------------------

### Full Middleware Test (FastAPI Example)

```python
import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI

from your_guard.middleware import SecurityMiddleware
from guard_core.models import SecurityConfig


@pytest.fixture
def app():
    config = SecurityConfig(
        enable_redis=False,
        blacklist=["10.0.0.1"],
    )

    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def root():
        return {"status": "ok"}

    return app


@pytest.fixture
async def client(app):
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_allowed_request(client):
    response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_blacklisted_ip(client):
    response = await client.get("/", headers={"X-Forwarded-For": "10.0.0.1"})
    assert response.status_code == 403
```

### Testing with Decorators

```python
@pytest.fixture
def decorated_app():
    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    guard = SecurityDecorator(config)
    app.state.guard_decorator = guard

    middleware = SecurityMiddleware(app, config=config)
    middleware.set_decorator_handler(guard)
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/limited")
    @guard.rate_limit(max_requests=2, window=60)
    async def limited():
        return {"status": "ok"}

    return app
```

### Testing Singleton Cleanup

Guard-core uses singletons for `IPBanManager`, `SusPatternsManager`, and `SecurityHeadersManager`. Always reset them in your test suite:

```python
@pytest.fixture(autouse=True)
def cleanup_singletons():
    from guard_core.handlers.ipban_handler import IPBanManager
    from guard_core.handlers.security_headers_handler import SecurityHeadersManager
    from guard_core.handlers.suspatterns_handler import SusPatternsManager

    IPBanManager._instance = None
    SusPatternsManager._instance = None
    SecurityHeadersManager._instance = None
    yield
    IPBanManager._instance = None
    SusPatternsManager._instance = None
    SecurityHeadersManager._instance = None
```

### Testing Without Redis

Pass `enable_redis=False` to `SecurityConfig` for all unit tests that do not require distributed state. This avoids needing a running Redis instance:

```python
config = SecurityConfig(enable_redis=False)
```

For integration tests that require Redis, use a test fixture with a real or mock Redis connection:

```python
import os

@pytest.fixture
def redis_config():
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    return SecurityConfig(
        enable_redis=True,
        redis_url=redis_url,
        redis_prefix="test_guard:",
    )
```

Test Configuration
------------------

Guard-core uses `asyncio_mode = "auto"` in `pyproject.toml`. Your adapter should do the same:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
python_files = ["test_*.py"]
addopts = "--cov=your_guard --cov-report=term-missing"
```
