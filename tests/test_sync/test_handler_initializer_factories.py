import logging
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.events.metrics import MetricsCollector
from guard_core.sync.core.events.middleware_events import SecurityEventBus
from guard_core.sync.core.initialization.handler_initializer import (
    HandlerInitializer,
)


def _initializer(config: SecurityConfig) -> HandlerInitializer:
    agent = MagicMock()
    agent.start = MagicMock()
    agent.initialize_redis = MagicMock()
    return HandlerInitializer(config=config, agent_handler=agent)


def test_build_event_bus_returns_configured_instance() -> None:
    config = SecurityConfig(
        muted_event_types={"penetration_attempt"},
        agent_enable_events=True,
    )
    initializer = _initializer(config)
    with (
        patch.object(initializer, "initialize_agent_for_handlers", MagicMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", MagicMock()),
    ):
        initializer.initialize_agent_integrations()

    bus = initializer.build_event_bus()
    assert isinstance(bus, SecurityEventBus)
    assert bus.event_filter.muted_event_types == frozenset({"penetration_attempt"})
    assert bus.agent_handler is initializer.composite_handler


def test_build_metrics_collector_returns_configured_instance() -> None:
    config = SecurityConfig(muted_metric_types={"response_time"})
    initializer = _initializer(config)
    with (
        patch.object(initializer, "initialize_agent_for_handlers", MagicMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", MagicMock()),
    ):
        initializer.initialize_agent_integrations()

    collector = initializer.build_metrics_collector()
    assert isinstance(collector, MetricsCollector)
    assert collector.event_filter.muted_metric_types == frozenset({"response_time"})
    assert collector.agent_handler is initializer.composite_handler


def test_initialize_agent_integrations_starts_composite_handler() -> None:
    config = SecurityConfig(enable_otel=True)
    initializer = HandlerInitializer(config=config, agent_handler=None)
    fake_composite = MagicMock()
    with (
        patch.object(
            initializer, "build_composite_handler", return_value=fake_composite
        ),
        patch.object(initializer, "initialize_agent_for_handlers", MagicMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", MagicMock()),
    ):
        initializer.initialize_agent_integrations()

    fake_composite.start.assert_called_once()


def test_shutdown_agent_integrations_stops_composite_handler() -> None:
    config = SecurityConfig(enable_otel=True)
    initializer = HandlerInitializer(config=config, agent_handler=None)
    fake_composite = MagicMock()
    with (
        patch.object(
            initializer, "build_composite_handler", return_value=fake_composite
        ),
        patch.object(initializer, "initialize_agent_for_handlers", MagicMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", MagicMock()),
    ):
        initializer.initialize_agent_integrations()
        initializer.shutdown_agent_integrations()

    fake_composite.stop.assert_called_once()


def test_shutdown_is_idempotent() -> None:
    config = SecurityConfig(enable_otel=True)
    initializer = HandlerInitializer(config=config, agent_handler=None)
    fake_composite = MagicMock()
    with (
        patch.object(
            initializer, "build_composite_handler", return_value=fake_composite
        ),
        patch.object(initializer, "initialize_agent_for_handlers", MagicMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", MagicMock()),
    ):
        initializer.initialize_agent_integrations()
        initializer.shutdown_agent_integrations()
        initializer.shutdown_agent_integrations()

    fake_composite.stop.assert_called_once()
    assert initializer.composite_handler is None
    assert initializer.event_filter is None


def test_shutdown_noop_when_not_initialized() -> None:
    config = SecurityConfig()
    initializer = HandlerInitializer(config=config, agent_handler=None)
    initializer.shutdown_agent_integrations()


def test_build_event_bus_before_init_raises() -> None:
    initializer = _initializer(SecurityConfig())
    with pytest.raises(RuntimeError, match="initialize_agent_integrations"):
        initializer.build_event_bus()


def test_build_metrics_collector_before_init_raises() -> None:
    initializer = _initializer(SecurityConfig())
    with pytest.raises(RuntimeError, match="initialize_agent_integrations"):
        initializer.build_metrics_collector()


def test_composite_start_exception_is_logged_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(enable_otel=True)
    initializer = HandlerInitializer(config=config, agent_handler=None)

    from guard_core.sync.core.events.composite_handler import CompositeAgentHandler

    failing = MagicMock()
    failing.start.side_effect = RuntimeError("boom")
    composite = CompositeAgentHandler([failing])

    with (
        patch.object(initializer, "build_composite_handler", return_value=composite),
        patch.object(initializer, "initialize_agent_for_handlers", MagicMock()),
        patch.object(initializer, "initialize_dynamic_rule_manager", MagicMock()),
        caplog.at_level(logging.ERROR, logger="guard_core"),
    ):
        initializer.initialize_agent_integrations()

    assert any("handler.start failed" in r.message for r in caplog.records)
