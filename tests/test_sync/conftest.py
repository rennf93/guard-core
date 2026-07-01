import os
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from pytest import TempPathFactory

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN") or "test_token"
REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"
REDIS_PREFIX = os.getenv("REDIS_PREFIX") or "test:guard_core:"


class MockState:
    def __init__(self) -> None:
        self._attrs: dict[str, Any] = {}

    def __getattr__(self, name: str) -> Any:
        if name == "_attrs":
            return super().__getattribute__(name)
        return self._attrs.get(name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "_attrs":
            super().__setattr__(name, value)
        else:
            self._attrs[name] = value


class SyncMockGuardRequest:
    def __init__(
        self,
        path: str = "/",
        method: str = "GET",
        headers: dict[str, str] | None = None,
        client_host: str | None = "127.0.0.1",
        scheme: str = "https",
        query_params: dict[str, str] | None = None,
        body_content: bytes = b"",
        scope: dict[str, Any] | None = None,
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
    def headers(self) -> dict[str, str]:
        return self._headers

    @property
    def query_params(self) -> dict[str, str]:
        return self._query_params

    def body(self) -> bytes:
        return self._body

    @property
    def state(self) -> MockState:
        return self._state

    @property
    def scope(self) -> dict[str, Any]:
        return self._scope


class MockGuardResponse:
    def __init__(
        self,
        content: str = "",
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._status_code = status_code
        self._headers: dict[str, str] = headers or {}
        self._body = content.encode() if isinstance(content, str) else content

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def headers(self) -> dict[str, str]:
        return self._headers

    @property
    def body(self) -> bytes:
        return self._body


class MockGuardResponseFactory:
    def create_response(self, content: str, status_code: int) -> MockGuardResponse:
        return MockGuardResponse(content, status_code)

    def create_redirect_response(self, url: str, status_code: int) -> MockGuardResponse:
        return MockGuardResponse(f"Redirect to {url}", status_code, {"Location": url})


@pytest.fixture(autouse=True)
def reset_state() -> Generator[None, None]:
    IPBanManager._instance = None

    cloud_instance = cloud_handler._instance
    if cloud_instance:
        from guard_core.sync.handlers.cloud_ip_stores import InMemoryCloudIpStore

        cloud_instance.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}
        cloud_instance.redis_handler = None
        cloud_instance.agent_handler = None
        cloud_instance._store = InMemoryCloudIpStore()

    if IPInfoManager._instance:
        if IPInfoManager._instance.reader:
            IPInfoManager._instance.reader.close()
        IPInfoManager._instance.agent_handler = None
        IPInfoManager._instance = None

    yield
    spm = type(sus_patterns_handler)
    spm._instance = sus_patterns_handler
    spm._config = None
    sus_patterns_handler.patterns = [p[0] for p in spm._pattern_definitions]
    sus_patterns_handler.custom_patterns = set()
    sus_patterns_handler.compiled_custom_patterns = set()

    IPBanManager._instance = None


@pytest.fixture
def security_config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )


@pytest.fixture(scope="session")
def ipinfo_db_path(tmp_path_factory: TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("ipinfo_data") / "country_asn.mmdb"


@pytest.fixture
def security_config_redis(ipinfo_db_path: Path) -> SecurityConfig:
    return SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )


@pytest.fixture(autouse=True)
def redis_cleanup() -> Generator[None, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
    )
    redis_handler = RedisManager(config)
    redis_handler.initialize()
    try:
        redis_handler.delete_pattern(f"{REDIS_PREFIX}*")
    except Exception:
        pass
    finally:
        redis_handler.close()
    yield
    redis_handler = RedisManager(config)
    redis_handler.initialize()
    try:
        redis_handler.delete_pattern(f"{REDIS_PREFIX}*")
    except Exception:
        pass
    finally:
        redis_handler.close()


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> Generator[None, None]:
    config = SecurityConfig(enable_redis=False)
    rate_limit = rate_limit_handler(config)
    rate_limit.reset()
    yield


@pytest.fixture
def clean_rate_limiter() -> None:
    from guard_core.sync.handlers.ratelimit_handler import RateLimitManager

    RateLimitManager._instance = None
