import threading
from unittest.mock import MagicMock

from guard_core.models import SecurityConfig
from guard_core.sync.core.bypass.context import BypassContext
from guard_core.sync.core.bypass.handler import BypassHandler
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.scripts.rate_lua import RATE_LIMIT_SCRIPT


def test_rate_lua_script_exists() -> None:
    assert isinstance(RATE_LIMIT_SCRIPT, str)
    assert "ZADD" in RATE_LIMIT_SCRIPT


def _make_bypass_handler() -> BypassHandler:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    context = BypassContext(
        config=config,
        logger=MagicMock(),
        event_bus=MagicMock(),
        route_resolver=MagicMock(),
        response_factory=MagicMock(),
        validator=MagicMock(),
    )
    return BypassHandler(context)


def test_bypass_passthrough_no_client_with_call_next() -> None:
    handler = _make_bypass_handler()
    mock_request = MagicMock()
    mock_request.client_host = None
    mock_call_next = MagicMock(return_value=MagicMock())

    handler.context.response_factory.apply_modifier = MagicMock(side_effect=lambda r: r)

    result = handler.handle_passthrough(mock_request, call_next=mock_call_next)
    assert result is not None
    mock_call_next.assert_called_once_with(mock_request)


def test_bypass_passthrough_excluded_path_with_call_next() -> None:
    handler = _make_bypass_handler()
    mock_request = MagicMock()
    mock_request.client_host = "127.0.0.1"
    handler.context.validator.is_path_excluded = MagicMock(return_value=True)
    mock_call_next = MagicMock(return_value=MagicMock())

    handler.context.response_factory.apply_modifier = MagicMock(side_effect=lambda r: r)

    result = handler.handle_passthrough(mock_request, call_next=mock_call_next)
    assert result is not None
    mock_call_next.assert_called_once_with(mock_request)


def test_bypass_passthrough_no_client_without_call_next() -> None:
    handler = _make_bypass_handler()
    mock_request = MagicMock()
    mock_request.client_host = None

    result = handler.handle_passthrough(mock_request)
    assert result is None


def test_bypass_passthrough_excluded_path_without_call_next() -> None:
    handler = _make_bypass_handler()
    mock_request = MagicMock()
    mock_request.client_host = "127.0.0.1"
    handler.context.validator.is_path_excluded = MagicMock(return_value=True)

    result = handler.handle_passthrough(mock_request)
    assert result is None


def test_bypass_security_bypass_without_call_next() -> None:
    handler = _make_bypass_handler()
    mock_request = MagicMock()
    mock_request.url_path = "/test"
    mock_route_config = MagicMock()
    mock_route_config.bypassed_checks = {"all"}

    handler.context.config.passive_mode = False
    handler.context.route_resolver.should_bypass_check = MagicMock(return_value=True)

    result = handler.handle_security_bypass(
        mock_request, route_config=mock_route_config
    )
    assert result is None


def test_bypass_security_bypass_with_call_next() -> None:
    handler = _make_bypass_handler()
    mock_request = MagicMock()
    mock_request.url_path = "/test"
    mock_route_config = MagicMock()
    mock_route_config.bypassed_checks = {"all"}

    handler.context.config.passive_mode = False
    handler.context.route_resolver.should_bypass_check = MagicMock(return_value=True)
    mock_call_next = MagicMock(return_value=MagicMock())
    handler.context.response_factory.apply_modifier = MagicMock(side_effect=lambda r: r)

    result = handler.handle_security_bypass(
        mock_request,
        call_next=mock_call_next,
        route_config=mock_route_config,
    )
    assert result is not None
    mock_call_next.assert_called_once_with(mock_request)


def test_dynamic_rule_manager_stop_with_active_thread() -> None:
    DynamicRuleManager._instance = None
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    manager = DynamicRuleManager(config)

    stop_flag = threading.Event()

    def fake_loop() -> None:
        stop_flag.wait(timeout=10)

    manager.update_task = threading.Thread(target=fake_loop, daemon=True)
    manager.update_task.start()

    assert manager.update_task.is_alive()

    stop_flag.set()
    manager.stop()

    assert manager.update_task is None

    DynamicRuleManager._instance = None
