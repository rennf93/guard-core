from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.events.middleware_events import SecurityEventBus
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


def _config(**overrides: object) -> SecurityConfig:
    return SecurityConfig(enable_redis=False, **overrides)


async def test_metrics_collector_no_agent() -> None:
    collector = MetricsCollector(None, _config())
    await collector.send_metric("test", 1.0)


async def test_metrics_collector_disabled() -> None:
    agent = MagicMock()
    collector = MetricsCollector(agent, _config(agent_enable_metrics=False))
    await collector.send_metric("test", 1.0)
    agent.send_metric.assert_not_called()


async def test_metrics_collector_sends_metric() -> None:
    agent = MagicMock()
    agent.send_metric = AsyncMock()
    collector = MetricsCollector(agent, _config(agent_enable_metrics=True))
    with patch(
        "guard_core.core.events.metrics.SecurityMetric", create=True
    ) as mock_metric_cls:
        mock_metric_cls.return_value = MagicMock()
        await collector.send_metric("response_time", 0.5, {"endpoint": "/api"})
    agent.send_metric.assert_called_once()


async def test_metrics_collector_send_metric_exception() -> None:
    agent = MagicMock()
    agent.send_metric = AsyncMock(side_effect=Exception("fail"))
    collector = MetricsCollector(agent, _config(agent_enable_metrics=True))
    with patch("guard_core.core.events.metrics.SecurityMetric", create=True):
        await collector.send_metric("test", 1.0)


async def test_metrics_collect_request_no_agent() -> None:
    collector = MetricsCollector(None, _config())
    req = MockGuardRequest(path="/api", method="GET")
    await collector.collect_request_metrics(req, 0.1, 200)


async def test_metrics_collect_request_with_agent() -> None:
    agent = MagicMock()
    agent.send_metric = AsyncMock()
    collector = MetricsCollector(agent, _config(agent_enable_metrics=True))
    req = MockGuardRequest(path="/api", method="GET")
    with patch("guard_core.core.events.metrics.SecurityMetric", create=True):
        await collector.collect_request_metrics(req, 0.1, 200)
    assert agent.send_metric.call_count == 2


async def test_metrics_collect_request_error_status() -> None:
    agent = MagicMock()
    agent.send_metric = AsyncMock()
    collector = MetricsCollector(agent, _config(agent_enable_metrics=True))
    req = MockGuardRequest(path="/api", method="GET")
    with patch("guard_core.core.events.metrics.SecurityMetric", create=True):
        await collector.collect_request_metrics(req, 0.1, 500)
    assert agent.send_metric.call_count == 3


async def test_event_bus_no_agent() -> None:
    bus = SecurityEventBus(None, _config())
    req = MockGuardRequest()
    await bus.send_middleware_event("test", req, "blocked", "reason")


async def test_event_bus_disabled() -> None:
    agent = MagicMock()
    bus = SecurityEventBus(agent, _config(agent_enable_events=False))
    req = MockGuardRequest()
    await bus.send_middleware_event("test", req, "blocked", "reason")
    agent.send_event.assert_not_called()


async def test_event_bus_sends_event() -> None:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    bus = SecurityEventBus(agent, _config(agent_enable_events=True))
    req = MockGuardRequest()
    with patch(
        "guard_core.core.events.middleware_events.extract_client_ip",
        new_callable=AsyncMock,
        return_value="1.2.3.4",
    ):
        with patch(
            "guard_core.core.events.middleware_events.SecurityEvent", create=True
        ) as mock_event:
            mock_event.return_value = MagicMock()
            await bus.send_middleware_event("test", req, "blocked", "reason")
    agent.send_event.assert_called_once()


async def test_event_bus_sends_event_with_geo() -> None:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="US")
    bus = SecurityEventBus(agent, _config(agent_enable_events=True), geo_ip_handler=geo)
    req = MockGuardRequest()
    with patch(
        "guard_core.core.events.middleware_events.extract_client_ip",
        new_callable=AsyncMock,
        return_value="1.2.3.4",
    ):
        with patch(
            "guard_core.core.events.middleware_events.SecurityEvent", create=True
        ) as mock_event:
            mock_event.return_value = MagicMock()
            await bus.send_middleware_event("test", req, "blocked", "reason")
    agent.send_event.assert_called_once()


async def test_event_bus_sends_event_exception() -> None:
    agent = MagicMock()
    agent.send_event = AsyncMock(side_effect=Exception("fail"))
    bus = SecurityEventBus(agent, _config(agent_enable_events=True))
    req = MockGuardRequest()
    with patch(
        "guard_core.core.events.middleware_events.extract_client_ip",
        new_callable=AsyncMock,
        return_value="1.2.3.4",
    ):
        with patch(
            "guard_core.core.events.middleware_events.SecurityEvent", create=True
        ):
            await bus.send_middleware_event("test", req, "blocked", "reason")


async def test_event_bus_https_violation_route_config() -> None:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    bus = SecurityEventBus(agent, _config(agent_enable_events=True))
    mock_send = AsyncMock()
    cast(Any, bus).send_middleware_event = mock_send
    req = MockGuardRequest(scheme="http")
    rc = RouteConfig()
    rc.require_https = True
    await bus.send_https_violation_event(req, rc)
    cast(Mock, bus.send_middleware_event).assert_called_once()
    call_kwargs = cast(Mock, bus.send_middleware_event).call_args
    assert call_kwargs.kwargs["event_type"] == "decorator_violation"


async def test_event_bus_https_violation_global() -> None:
    bus = SecurityEventBus(None, _config())
    mock_send = AsyncMock()
    cast(Any, bus).send_middleware_event = mock_send
    req = MockGuardRequest(scheme="http")
    await bus.send_https_violation_event(req, None)
    cast(Mock, bus.send_middleware_event).assert_called_once()
    call_kwargs = cast(Mock, bus.send_middleware_event).call_args
    assert call_kwargs.kwargs["event_type"] == "https_enforced"


async def test_event_bus_cloud_detection_with_details() -> None:
    agent = MagicMock()
    bus = SecurityEventBus(agent, _config(agent_enable_events=True))
    mock_send = AsyncMock()
    cast(Any, bus).send_middleware_event = mock_send
    req = MockGuardRequest()
    cloud_handler = MagicMock()
    cloud_handler.get_cloud_provider_details = MagicMock(
        return_value=("AWS", "10.0.0.0/8")
    )
    cloud_handler.agent_handler = MagicMock()
    cloud_handler.send_cloud_detection_event = AsyncMock()
    rc = RouteConfig()
    rc.block_cloud_providers = {"AWS"}
    await bus.send_cloud_detection_events(
        req, "1.2.3.4", ["AWS"], rc, cloud_handler, False
    )
    cloud_handler.send_cloud_detection_event.assert_called_once()
    cast(Mock, bus.send_middleware_event).assert_called_once()


async def test_event_bus_cloud_detection_no_details() -> None:
    bus = SecurityEventBus(None, _config())
    mock_send2 = AsyncMock()
    cast(Any, bus).send_middleware_event = mock_send2
    req = MockGuardRequest()
    cloud_handler = MagicMock()
    cloud_handler.get_cloud_provider_details = MagicMock(return_value=None)
    cloud_handler.agent_handler = None
    await bus.send_cloud_detection_events(
        req, "1.2.3.4", ["AWS"], None, cloud_handler, False
    )
    cast(Mock, bus.send_middleware_event).assert_not_called()


async def test_event_bus_geo_exception() -> None:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    geo = MagicMock()
    geo.get_country = MagicMock(side_effect=Exception("geo fail"))
    bus = SecurityEventBus(agent, _config(agent_enable_events=True), geo_ip_handler=geo)
    req = MockGuardRequest()
    with patch(
        "guard_core.core.events.middleware_events.extract_client_ip",
        new_callable=AsyncMock,
        return_value="1.2.3.4",
    ):
        with patch(
            "guard_core.core.events.middleware_events.SecurityEvent", create=True
        ) as mock_event:
            mock_event.return_value = MagicMock()
            await bus.send_middleware_event("test", req, "blocked", "reason")
    agent.send_event.assert_called_once()


async def test_metrics_collector_filtered_metric() -> None:
    agent = MagicMock()
    agent.send_metric = AsyncMock()
    from guard_core.core.events.event_types import METRIC_RESPONSE_TIME, EventFilter

    collector = MetricsCollector(
        agent,
        _config(agent_enable_metrics=True),
        event_filter=EventFilter(muted_metric_types=frozenset({METRIC_RESPONSE_TIME})),
    )
    with patch("guard_core.core.events.metrics.SecurityMetric", create=True):
        await collector.send_metric(METRIC_RESPONSE_TIME, 0.5, {"endpoint": "/api"})
    agent.send_metric.assert_not_called()
