from collections.abc import Callable
from typing import cast
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.bypass.context import BypassContext
from guard_core.sync.core.bypass.handler import BypassHandler
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


@pytest.fixture
def mock_response_factory() -> Mock:
    factory = Mock()
    factory.apply_modifier = MagicMock(return_value=Mock(status_code=200))
    return factory


@pytest.fixture
def mock_validator() -> Mock:
    validator = Mock()
    validator.is_path_excluded = MagicMock(return_value=False)
    return validator


@pytest.fixture
def mock_route_resolver() -> Mock:
    resolver = Mock()
    resolver.should_bypass_check = Mock(return_value=False)
    return resolver


@pytest.fixture
def mock_event_bus() -> Mock:
    event_bus = Mock()
    event_bus.send_middleware_event = MagicMock()
    return event_bus


@pytest.fixture
def mock_config() -> Mock:
    config = Mock()
    config.passive_mode = False
    return config


@pytest.fixture
def bypass_context(
    mock_config: Mock,
    mock_response_factory: Mock,
    mock_validator: Mock,
    mock_route_resolver: Mock,
    mock_event_bus: Mock,
) -> BypassContext:
    return BypassContext(
        config=mock_config,
        logger=Mock(),
        response_factory=mock_response_factory,
        validator=mock_validator,
        route_resolver=mock_route_resolver,
        event_bus=mock_event_bus,
    )


@pytest.fixture
def bypass_handler(bypass_context: BypassContext) -> BypassHandler:
    return BypassHandler(bypass_context)


@pytest.fixture
def mock_request() -> Mock:
    request = Mock()
    request.url_path = "/test"
    request.client_host = "127.0.0.1"
    return request


@pytest.fixture
def call_next() -> Callable[[Mock], Mock]:
    def _call_next(request: Mock) -> Mock:
        return Mock(status_code=200)

    return _call_next


def test_init(bypass_context: BypassContext) -> None:
    handler = BypassHandler(bypass_context)
    assert handler.context == bypass_context


def test_handle_passthrough_no_client(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_response_factory: Mock,
) -> None:
    mock_request.client_host = None

    response = bypass_handler.handle_passthrough(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
    )

    assert response is not None
    assert response.status_code == 200
    mock_response_factory.apply_modifier.assert_called_once()


def test_handle_passthrough_excluded_path(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_validator: Mock,
    mock_response_factory: Mock,
) -> None:
    mock_validator.is_path_excluded.return_value = True

    response = bypass_handler.handle_passthrough(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
    )

    assert response is not None
    assert response.status_code == 200
    mock_validator.is_path_excluded.assert_called_once_with(mock_request)
    mock_response_factory.apply_modifier.assert_called_once()


def test_handle_passthrough_no_bypass(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_validator: Mock,
) -> None:
    mock_validator.is_path_excluded.return_value = False

    response = bypass_handler.handle_passthrough(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
    )

    assert response is None
    mock_validator.is_path_excluded.assert_called_once_with(mock_request)


def test_handle_security_bypass_no_route_config(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
) -> None:
    response = bypass_handler.handle_security_bypass(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
        None,
    )

    assert response is None


def test_handle_security_bypass_should_not_bypass(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_route_resolver: Mock,
) -> None:
    route_config = RouteConfig()
    route_config.bypassed_checks = {"ip_check"}
    mock_route_resolver.should_bypass_check.return_value = False

    response = bypass_handler.handle_security_bypass(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
        route_config,
    )

    assert response is None
    mock_route_resolver.should_bypass_check.assert_called_once_with("all", route_config)


def test_handle_security_bypass_active_mode(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_route_resolver: Mock,
    mock_event_bus: Mock,
    mock_response_factory: Mock,
    bypass_context: BypassContext,
) -> None:
    route_config = RouteConfig()
    route_config.bypassed_checks = {"all"}
    mock_route_resolver.should_bypass_check.return_value = True
    bypass_context.config.passive_mode = False

    response = bypass_handler.handle_security_bypass(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
        route_config,
    )

    assert response is not None
    assert response.status_code == 200
    mock_event_bus.send_middleware_event.assert_called_once()
    call_args = mock_event_bus.send_middleware_event.call_args[1]
    assert call_args["event_type"] == "security_bypass"
    assert call_args["action_taken"] == "all_checks_bypassed"
    assert call_args["endpoint"] == "/test"
    mock_response_factory.apply_modifier.assert_called_once()


def test_handle_security_bypass_passive_mode(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_route_resolver: Mock,
    mock_event_bus: Mock,
    mock_response_factory: Mock,
    bypass_context: BypassContext,
) -> None:
    route_config = RouteConfig()
    route_config.bypassed_checks = {"all"}
    mock_route_resolver.should_bypass_check.return_value = True
    bypass_context.config.passive_mode = True

    response = bypass_handler.handle_security_bypass(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
        route_config,
    )

    assert response is None
    mock_event_bus.send_middleware_event.assert_called_once()
    mock_response_factory.apply_modifier.assert_not_called()


def test_handle_security_bypass_with_multiple_bypassed_checks(
    bypass_handler: BypassHandler,
    mock_request: Mock,
    call_next: Callable[[Mock], Mock],
    mock_route_resolver: Mock,
    mock_event_bus: Mock,
    bypass_context: BypassContext,
) -> None:
    route_config = RouteConfig()
    route_config.bypassed_checks = {"ip_check", "rate_limit", "https_check"}
    mock_route_resolver.should_bypass_check.return_value = True
    bypass_context.config.passive_mode = False

    response = bypass_handler.handle_security_bypass(
        mock_request,
        cast(Callable[[SyncGuardRequest], GuardResponse], call_next),
        route_config,
    )

    assert response is not None
    mock_event_bus.send_middleware_event.assert_called_once()
    call_args = mock_event_bus.send_middleware_event.call_args[1]
    assert set(call_args["bypassed_checks"]) == {
        "ip_check",
        "rate_limit",
        "https_check",
    }
