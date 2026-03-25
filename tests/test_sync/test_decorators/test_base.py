from unittest.mock import Mock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.decorators.base import (
    BaseSecurityDecorator,
    BaseSecurityMixin,
    RouteConfig,
    get_route_decorator_config,
)
from tests.test_sync.conftest import SyncMockGuardRequest


def test_route_config_initialization() -> None:
    config = RouteConfig()

    assert config.rate_limit is None
    assert config.rate_limit_window is None
    assert config.ip_whitelist is None
    assert config.ip_blacklist is None
    assert config.blocked_countries is None
    assert config.whitelist_countries is None
    assert config.bypassed_checks == set()
    assert config.require_https is False
    assert config.auth_required is None
    assert config.custom_validators == []
    assert config.blocked_user_agents == []
    assert config.required_headers == {}
    assert config.behavior_rules == []
    assert config.block_cloud_providers == set()
    assert config.max_request_size is None
    assert config.allowed_content_types is None
    assert config.time_restrictions is None
    assert config.enable_suspicious_detection is True
    assert config.require_referrer is None
    assert config.api_key_required is False
    assert config.session_limits is None


def test_base_security_mixin_not_implemented() -> None:
    mixin = BaseSecurityMixin()

    mock_func = Mock()

    with pytest.raises(
        NotImplementedError, match="This mixin must be used with BaseSecurityDecorator"
    ):
        mixin._ensure_route_config(mock_func)

    with pytest.raises(
        NotImplementedError, match="This mixin must be used with BaseSecurityDecorator"
    ):
        mixin._apply_route_config(mock_func)


def test_base_security_decorator(security_config: SecurityConfig) -> None:
    decorator = BaseSecurityDecorator(security_config)

    assert decorator.config == security_config
    assert decorator._route_configs == {}
    assert decorator.behavior_tracker is not None

    mock_func = Mock()
    mock_func.__module__ = "test_module"
    mock_func.__qualname__ = "test_function"

    route_id = decorator._get_route_id(mock_func)
    assert route_id == "test_module.test_function"

    route_config = decorator._ensure_route_config(mock_func)
    assert isinstance(route_config, RouteConfig)
    assert (
        route_config.enable_suspicious_detection
        == security_config.enable_penetration_detection
    )

    route_config2 = decorator._ensure_route_config(mock_func)
    assert route_config is route_config2

    retrieved_config = decorator.get_route_config(route_id)
    assert retrieved_config is route_config

    non_existent_config = decorator.get_route_config("non.existent.route")
    assert non_existent_config is None

    decorated_func = decorator._apply_route_config(mock_func)
    assert decorated_func is mock_func
    assert hasattr(decorated_func, "_guard_route_id")
    assert decorated_func._guard_route_id == route_id


def test_get_route_decorator_config() -> None:
    security_config = SecurityConfig()
    decorator = BaseSecurityDecorator(security_config)

    mock_request = SyncMockGuardRequest()
    result = get_route_decorator_config(mock_request, decorator)
    assert result is None

    route_id = "test.route.id"
    route_config = decorator._ensure_route_config(
        Mock(__module__="test", __qualname__="route")
    )
    decorator._route_configs[route_id] = route_config

    mock_request._state.guard_route_id = route_id
    result = get_route_decorator_config(mock_request, decorator)
    assert result is route_config


def test_initialize_behavior_tracking(security_config: SecurityConfig) -> None:
    decorator = BaseSecurityDecorator(security_config)

    decorator.initialize_behavior_tracking()

    mock_redis_handler = Mock()
    decorator.initialize_behavior_tracking(mock_redis_handler)
