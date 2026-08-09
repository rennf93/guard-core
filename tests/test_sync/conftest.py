import os
import re
import sys
from collections.abc import Generator
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import FrameType
from typing import Any

import pytest
from pytest import TempPathFactory

from guard_core.models import SecurityConfig
from guard_core.sync.handlers import suspatterns_handler as _suspatterns_module
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_handler,
)

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN") or "test_token"
REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"
REDIS_PREFIX = os.getenv("REDIS_PREFIX") or "test:guard_core:"

_DETECTION_SINGLETON_FIELDS = (
    "_compiler",
    "_preprocessor",
    "_semantic_analyzer",
    "_performance_monitor",
    "_semantic_threshold",
    "_threat_score_threshold",
)


@pytest.fixture(autouse=True)
def _isolate_detection_singleton() -> Any:
    handler = _suspatterns_module.sus_patterns_handler
    saved_fields = {
        name: getattr(handler, name) for name in _DETECTION_SINGLETON_FIELDS
    }
    saved_instance = SusPatternsManager._instance
    saved_config = SusPatternsManager._config
    saved_global = _suspatterns_module.sus_patterns_handler
    yield
    for name, value in saved_fields.items():
        setattr(handler, name, value)
    SusPatternsManager._instance = saved_instance
    SusPatternsManager._config = saved_config
    _suspatterns_module.sus_patterns_handler = saved_global


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
    sus_patterns_handler.compiled_patterns = [
        (re.compile(pattern, re.IGNORECASE | re.MULTILINE), contexts, category)
        for pattern, contexts, category in spm._pattern_definitions
    ]
    sus_patterns_handler.custom_patterns = set()
    sus_patterns_handler.compiled_custom_patterns = set()

    IPBanManager._instance = None

    dynamic_rule_instance = DynamicRuleManager._instance
    if dynamic_rule_instance and dynamic_rule_instance.update_task:
        dynamic_rule_instance.stop()
    DynamicRuleManager._instance = None


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


_GUARD_AGENT_FINDER_ATTR = "_guard_core_agent_import_finder"


def _calling_module_name(frame: FrameType | None) -> str | None:
    while frame is not None:
        filename = frame.f_code.co_filename
        if "importlib" not in filename and not filename.startswith("<frozen"):
            name: str | None = frame.f_globals.get("__name__")
            return name
        frame = frame.f_back
    return None


def _is_guard_core_module(name: str | None) -> bool:
    return name is not None and (name == "guard_core" or name.startswith("guard_core."))


def _guard_agent_import_is_allowed(caller: str, fullname: str) -> bool:
    if caller == "guard_core._pydantic_plugin_mute":
        return True
    return caller == "guard_core.models" and fullname == "guard_agent"


class _GuardAgentImportFinder:
    def __init__(self) -> None:
        self.violations: list[str] = []

    def find_spec(
        self, fullname: str, path: Any, target: Any = None
    ) -> ModuleSpec | None:
        if fullname == "guard_agent" or fullname.startswith("guard_agent."):
            caller = _calling_module_name(sys._getframe(1))
            if (
                caller is not None
                and _is_guard_core_module(caller)
                and not _guard_agent_import_is_allowed(caller, fullname)
            ):
                self.violations.append(f"{caller} imports {fullname}")
        return None


_MUTED_PLUGIN_SETTINGS = {"logfire": {"record": "off"}}
_TELEMETRY_MODEL_NAMES = ("SecurityEvent", "SecurityMetric", "EventBatch")


def _unmuted_guard_agent_telemetry_models() -> list[str]:
    guard_agent_module = sys.modules.get("guard_agent")
    if guard_agent_module is None:
        return []
    return [
        name
        for name in _TELEMETRY_MODEL_NAMES
        if getattr(guard_agent_module, name).model_config.get("plugin_settings")
        != _MUTED_PLUGIN_SETTINGS
    ]


def pytest_configure(config: pytest.Config) -> None:
    if getattr(sys, _GUARD_AGENT_FINDER_ATTR, None) is not None:
        return
    finder = _GuardAgentImportFinder()
    sys.meta_path.insert(0, finder)
    setattr(sys, _GUARD_AGENT_FINDER_ATTR, finder)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    finder = getattr(sys, _GUARD_AGENT_FINDER_ATTR, None)
    if finder is not None:
        delattr(sys, _GUARD_AGENT_FINDER_ATTR)
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        assert not finder.violations, (
            "guard_agent imported outside the pydantic-plugin-mute allowlist: "
            + "; ".join(finder.violations)
        )
    unmuted = _unmuted_guard_agent_telemetry_models()
    assert not unmuted, (
        "guard_agent is in sys.modules at session end but these telemetry "
        "models were never muted: " + ", ".join(unmuted)
    )
