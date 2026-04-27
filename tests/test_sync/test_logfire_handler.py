from unittest.mock import MagicMock, patch

import pytest

from guard_core.sync.core.events.logfire_handler import LogfireHandler


@pytest.fixture
def config() -> MagicMock:
    return MagicMock(logfire_service_name="guard-core-test")


def test_health_check_true_when_available(config: MagicMock) -> None:
    with patch("guard_core.sync.core.events.logfire_handler._logfire_available", True):
        handler = LogfireHandler(config)
        assert handler.health_check() is True


def test_health_check_false_when_unavailable() -> None:
    with patch("guard_core.sync.core.events.logfire_handler._logfire_available", False):
        handler = LogfireHandler(MagicMock())
        assert handler.health_check() is False


def test_noop_when_logfire_unavailable(config: MagicMock) -> None:
    with patch("guard_core.sync.core.events.logfire_handler._logfire_available", False):
        handler = LogfireHandler(config)
        handler.send_event(MagicMock())
        handler.send_metric(MagicMock())
        handler.start()
        handler.stop()


def test_get_dynamic_rules_returns_none(config: MagicMock) -> None:
    handler = LogfireHandler(config)
    assert handler.get_dynamic_rules() is None


def test_send_event_creates_span(config: MagicMock) -> None:
    with (
        patch("guard_core.sync.core.events.logfire_handler._logfire_available", True),
        patch("guard_core.sync.core.events.logfire_handler.logfire") as mock_lf,
    ):
        mock_cm = MagicMock()
        mock_cm.__enter__ = MagicMock(return_value=None)
        mock_cm.__exit__ = MagicMock(return_value=False)
        mock_lf.span.return_value = mock_cm

        handler = LogfireHandler(config)
        event = MagicMock()
        event.event_type = "penetration_attempt"
        event.ip_address = "1.2.3.4"
        event.action_taken = "blocked"
        event.reason = "test"
        event.endpoint = "/test"
        event.method = "GET"
        event.status_code = 403

        handler.send_event(event)
        mock_lf.span.assert_called_once()
        call_kwargs = mock_lf.span.call_args[1]
        assert call_kwargs["event_type"] == "penetration_attempt"


def test_send_metric_records(config: MagicMock) -> None:
    with (
        patch("guard_core.sync.core.events.logfire_handler._logfire_available", True),
        patch("guard_core.sync.core.events.logfire_handler.logfire") as mock_lf,
    ):
        handler = LogfireHandler(config)
        metric = MagicMock()
        metric.metric_type = "response_time"
        metric.value = 0.5
        metric.endpoint = "/test"
        metric.tags = {"method": "GET"}

        handler.send_metric(metric)
        mock_lf.info.assert_called_once()
        call_args = mock_lf.info.call_args
        assert call_args.args[0] == "guard.metric.response_time"
        assert call_args.kwargs["value"] == 0.5
        assert call_args.kwargs["endpoint"] == "/test"
        assert call_args.kwargs["method"] == "GET"


def test_start_configures_logfire(config: MagicMock) -> None:
    with (
        patch("guard_core.sync.core.events.logfire_handler._logfire_available", True),
        patch("guard_core.sync.core.events.logfire_handler.logfire") as mock_lf,
    ):
        handler = LogfireHandler(config)
        handler.start()
        mock_lf.configure.assert_called_once_with(service_name="guard-core-test")


def test_flush_buffer_and_initialize_redis_and_stop_noop(
    config: MagicMock,
) -> None:
    handler = LogfireHandler(config)
    handler.flush_buffer()
    handler.initialize_redis(MagicMock())
    handler.stop()


def test_import_error_branch() -> None:
    import importlib
    import sys

    module_name = "guard_core.sync.core.events.logfire_handler"
    original = sys.modules.get(module_name)
    sys.modules.pop(module_name, None)
    sys.modules.pop("logfire", None)

    real_import = __import__

    def block_logfire(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: list[str] | None = None,
        level: int = 0,
    ) -> object:
        if name == "logfire":
            raise ImportError("logfire not installed")
        return real_import(name, globals, locals, fromlist or [], level)

    try:
        with patch("builtins.__import__", side_effect=block_logfire):
            mod = importlib.import_module(module_name)
            assert mod._logfire_available is False
    finally:
        sys.modules.pop(module_name, None)
        if original is not None:
            sys.modules[module_name] = original
            importlib.reload(original)
        else:
            importlib.import_module(module_name)
