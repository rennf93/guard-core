from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from guard_agent.models import AgentConfig, SecurityEvent, SecurityMetric

from guard_core.models import SecurityConfig


@pytest.fixture
def mock_guard_agent() -> Generator[Any, Any, Any]:
    import sys
    import types

    mock_guard_agent_module = types.ModuleType("guard_agent")
    mock_guard_agent_module.SecurityEvent = SecurityEvent  # type: ignore
    mock_guard_agent_module.SecurityMetric = SecurityMetric  # type: ignore
    mock_guard_agent_module.AgentConfig = AgentConfig  # type: ignore

    mock_models_module = types.ModuleType("guard_agent.models")
    mock_models_module.SecurityEvent = SecurityEvent  # type: ignore
    mock_models_module.SecurityMetric = SecurityMetric  # type: ignore
    mock_models_module.AgentConfig = AgentConfig  # type: ignore
    mock_guard_agent_module.models = mock_models_module  # type: ignore

    mock_agent_handler = MagicMock()
    mock_guard_agent_func = MagicMock(return_value=mock_agent_handler)
    mock_guard_agent_module.guard_agent = mock_guard_agent_func  # type: ignore

    original_modules = {}
    modules_to_mock = [
        "guard_agent",
        "guard_agent.models",
    ]

    for module_name in modules_to_mock:
        if module_name in sys.modules:
            original_modules[module_name] = sys.modules[module_name]

    sys.modules["guard_agent"] = mock_guard_agent_module
    sys.modules["guard_agent.models"] = mock_models_module

    with (
        patch(
            "guard_core.sync.handlers.behavior_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.sync.handlers.cloud_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.sync.handlers.dynamic_rule_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.decorators.base.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.sync.handlers.ipban_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.sync.handlers.ipinfo_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.sync.handlers.ratelimit_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.sync.handlers.redis_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.sync.handlers.suspatterns_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.sync.utils.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.models.AgentConfig",
            AgentConfig,
            create=True,
        ),
    ):
        try:
            yield mock_guard_agent_module
        finally:
            for module_name in modules_to_mock:
                if module_name in original_modules:
                    sys.modules[module_name] = original_modules[module_name]
                elif module_name in sys.modules:  # pragma: no cover
                    del sys.modules[module_name]


@pytest.fixture(autouse=True)
def mock_dependencies(mock_guard_agent: MagicMock) -> Generator[Any, Any, Any]:
    with (
        patch(
            "guard_core.sync.handlers.redis_handler.RedisManager.initialize",
        ),
        patch(
            "guard_core.sync.handlers.ipinfo_handler.IPInfoManager.__new__"
        ) as mock_ipinfo,
        patch(
            "guard_core.sync.handlers.cloud_handler.CloudManager.__new__"
        ) as mock_cloud,
    ):
        mock_ipinfo_instance = MagicMock()
        mock_ipinfo.return_value = mock_ipinfo_instance

        mock_cloud_instance = MagicMock()
        mock_cloud.return_value = mock_cloud_instance
        yield


@pytest.fixture
def config() -> SecurityConfig:
    return SecurityConfig(
        enable_agent=True,
        agent_api_key="test-api-key",
        agent_endpoint="http://test.example.com",
        enable_dynamic_rules=True,
        dynamic_rule_interval=5,
        enable_penetration_detection=True,
        enable_ip_banning=True,
        enable_rate_limiting=True,
        rate_limit=100,
        rate_limit_window=60,
        auto_ban_threshold=5,
    )


@pytest.fixture
def mock_agent_handler() -> MagicMock:
    handler = MagicMock()
    handler.get_dynamic_rules = MagicMock()
    handler.send_event = MagicMock()
    return handler


@pytest.fixture
def mock_redis_handler() -> MagicMock:
    return MagicMock()
