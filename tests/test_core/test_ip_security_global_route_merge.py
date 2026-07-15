from typing import Any, cast
from unittest.mock import AsyncMock, Mock, patch

import pytest

from guard_core.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    config = SecurityConfig()
    config.passive_mode = False
    return config


@pytest.fixture
def mock_middleware(security_config: SecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = security_config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=403))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.geo_ip_handler = None
    return middleware


@pytest.fixture
def ip_security_check(mock_middleware: Mock) -> IpSecurityCheck:
    return IpSecurityCheck(mock_middleware)


def _request_for(route_config: RouteConfig | None) -> Mock:
    request = Mock()
    request.state = Mock()
    request.state.client_ip = "1.2.3.4"
    request.state.route_config = route_config
    return request


def _unbanned() -> Any:
    mgr = patch(
        "guard_core.core.checks.implementations.ip_security.ip_ban_manager"
    ).start()
    mgr.is_ip_banned = AsyncMock(return_value=False)
    return mgr


@pytest.fixture(autouse=True)
def _patches() -> Any:
    _unbanned()
    patch("guard_core.core.checks.implementations.ip_security.log_activity").start()
    yield
    patch.stopall()


async def test_decorated_route_still_enforces_global_blacklist(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    security_config.blacklist = ["1.2.3.4"]
    route_config = RouteConfig()
    route_config.rate_limit = 5

    result = await ip_security_check.check(_request_for(route_config))

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "ip_blocked"


async def test_route_ip_whitelist_overrides_global_blacklist(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    security_config.blacklist = ["1.2.3.4"]
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    request = _request_for(route_config)

    result = await ip_security_check.check(request)

    assert result is None
    assert request.state.is_whitelisted is False


async def test_route_country_rules_keep_global_ip_blacklist_active(
    ip_security_check: IpSecurityCheck,
    security_config: SecurityConfig,
    mock_middleware: Mock,
) -> None:
    security_config.blacklist = ["1.2.3.4"]
    mock_middleware.geo_ip_handler = Mock()
    mock_middleware.geo_ip_handler.get_country = Mock(return_value="US")
    route_config = RouteConfig()
    route_config.blocked_countries = ["RU"]

    result = await ip_security_check.check(_request_for(route_config))

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "ip_blocked"
    assert event_call.kwargs["filter_type"] == "global"


async def test_route_without_ip_fields_leaves_global_whitelist_semantics(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    security_config.whitelist = ["9.9.9.9"]
    route_config = RouteConfig()
    route_config.rate_limit = 5
    request = _request_for(route_config)

    result = await ip_security_check.check(request)

    assert result is not None
    assert request.state.is_whitelisted is False


async def test_global_whitelist_match_sets_is_whitelisted_with_route_config(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    security_config.whitelist = ["1.2.3.4"]
    route_config = RouteConfig()
    route_config.rate_limit = 5
    request = _request_for(route_config)

    result = await ip_security_check.check(request)

    assert result is None
    assert request.state.is_whitelisted is True


async def test_route_whitelist_with_unparseable_ip_blocks_at_route_step(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    request = _request_for(route_config)
    request.state.client_ip = "not-an-ip"

    result = await ip_security_check.check(request)

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "decorator_violation"


async def test_global_check_unparseable_ip_with_route_whitelist_not_whitelisted(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    request = _request_for(route_config)
    request.state.client_ip = "not-an-ip"

    result = await ip_security_check._check_global_ip_restrictions(
        request, "not-an-ip", route_config
    )

    assert request.state.is_whitelisted is False
    assert result is not None


async def test_route_blacklist_only_still_enforces_global_whitelist(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    security_config.whitelist = ["1.1.1.1"]
    route_config = RouteConfig()
    route_config.ip_blacklist = ["6.6.6.6"]

    result = await ip_security_check.check(_request_for(route_config))

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "ip_blocked"
    assert event_call.kwargs["filter_type"] == "global"


async def test_route_blacklist_only_allows_globally_whitelisted_client(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    security_config.whitelist = ["1.2.3.4"]
    route_config = RouteConfig()
    route_config.ip_blacklist = ["6.6.6.6"]
    request = _request_for(route_config)

    result = await ip_security_check.check(request)

    assert result is None
    assert request.state.is_whitelisted is True


async def test_route_blocked_countries_only_still_enforces_global_blocked_countries(
    ip_security_check: IpSecurityCheck,
    security_config: SecurityConfig,
    mock_middleware: Mock,
) -> None:
    security_config.whitelist = []
    security_config.blacklist = []
    security_config.blocked_countries = frozenset({"CN"})
    mock_middleware.geo_ip_handler = Mock()
    mock_middleware.geo_ip_handler.get_country = Mock(return_value="CN")
    route_config = RouteConfig()
    route_config.blocked_countries = ["RU"]

    result = await ip_security_check.check(_request_for(route_config))

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "ip_blocked"
    assert event_call.kwargs["filter_type"] == "global"


async def test_route_whitelist_match_overrides_global_whitelist_default_deny(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    security_config.whitelist = ["1.1.1.1"]
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    request = _request_for(route_config)

    result = await ip_security_check.check(request)

    assert result is None
    assert request.state.is_whitelisted is False


async def test_route_whitelist_set_but_client_excluded_blocks_at_route_step(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    route_config = RouteConfig()
    route_config.ip_whitelist = ["9.9.9.9"]
    request = _request_for(route_config)

    result = await ip_security_check.check(request)

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "decorator_violation"


async def test_route_ip_whitelist_match_still_denied_by_route_country_mismatch(
    ip_security_check: IpSecurityCheck,
    security_config: SecurityConfig,
    mock_middleware: Mock,
) -> None:
    mock_middleware.geo_ip_handler = Mock()
    mock_middleware.geo_ip_handler.get_country = Mock(return_value="CN")
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    route_config.whitelist_countries = ["US"]
    request = _request_for(route_config)

    result = await ip_security_check.check(request)

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "decorator_violation"


async def test_route_ip_whitelist_match_does_not_bypass_global_blocked_countries(
    ip_security_check: IpSecurityCheck,
    security_config: SecurityConfig,
    mock_middleware: Mock,
) -> None:
    security_config.blocked_countries = frozenset({"CN"})
    mock_middleware.geo_ip_handler = Mock()
    mock_middleware.geo_ip_handler.get_country = Mock(return_value="CN")
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    request = _request_for(route_config)

    result = await ip_security_check.check(request)

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "ip_blocked"
    assert event_call.kwargs["filter_type"] == "global"


async def test_route_whitelist_countries_match_skips_global_blocked_countries(
    ip_security_check: IpSecurityCheck,
    security_config: SecurityConfig,
    mock_middleware: Mock,
) -> None:
    security_config.blocked_countries = frozenset({"US"})
    mock_middleware.geo_ip_handler = Mock()
    mock_middleware.geo_ip_handler.get_country = Mock(return_value="US")
    route_config = RouteConfig()
    route_config.whitelist_countries = ["US"]
    request = _request_for(route_config)

    result = await ip_security_check.check(request)

    assert result is None
    assert request.state.is_whitelisted is False


async def test_route_ip_whitelist_overrides_route_ip_blacklist_same_ip(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    route_config.ip_blacklist = ["1.2.3.4"]
    request = _request_for(route_config)

    result = await ip_security_check.check(request)

    assert result is None
    assert request.state.is_whitelisted is False
