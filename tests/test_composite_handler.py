from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.events.composite_handler import CompositeAgentHandler


@pytest.fixture
def handler_a() -> AsyncMock:
    handler = AsyncMock()
    handler.send_event = AsyncMock()
    handler.send_metric = AsyncMock()
    handler.start = AsyncMock()
    handler.stop = AsyncMock()
    handler.flush_buffer = AsyncMock()
    handler.health_check = AsyncMock(return_value=True)
    handler.get_dynamic_rules = AsyncMock(return_value=None)
    handler.initialize_redis = AsyncMock()
    return handler


@pytest.fixture
def handler_b() -> AsyncMock:
    handler = AsyncMock()
    handler.send_event = AsyncMock()
    handler.send_metric = AsyncMock()
    handler.start = AsyncMock()
    handler.stop = AsyncMock()
    handler.flush_buffer = AsyncMock()
    handler.health_check = AsyncMock(return_value=True)
    handler.get_dynamic_rules = AsyncMock(return_value=None)
    handler.initialize_redis = AsyncMock()
    return handler


async def test_fanout_send_event(handler_a: AsyncMock, handler_b: AsyncMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    event = {"event_type": "penetration_attempt", "ip": "1.2.3.4"}
    await composite.send_event(event)
    handler_a.send_event.assert_awaited_once_with(event)
    handler_b.send_event.assert_awaited_once_with(event)


async def test_fanout_send_metric(handler_a: AsyncMock, handler_b: AsyncMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    metric = {"metric_type": "response_time", "value": 0.5}
    await composite.send_metric(metric)
    handler_a.send_metric.assert_awaited_once_with(metric)
    handler_b.send_metric.assert_awaited_once_with(metric)


async def test_delegates_start_stop(handler_a: AsyncMock, handler_b: AsyncMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    await composite.start()
    handler_a.start.assert_awaited_once()
    handler_b.start.assert_awaited_once()
    await composite.stop()
    handler_a.stop.assert_awaited_once()
    handler_b.stop.assert_awaited_once()


async def test_delegates_flush_buffer(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    await composite.flush_buffer()
    handler_a.flush_buffer.assert_awaited_once()
    handler_b.flush_buffer.assert_awaited_once()


async def test_delegates_initialize_redis(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    redis_handler = MagicMock()
    composite = CompositeAgentHandler([handler_a, handler_b])
    await composite.initialize_redis(redis_handler)
    handler_a.initialize_redis.assert_awaited_once_with(redis_handler)
    handler_b.initialize_redis.assert_awaited_once_with(redis_handler)


async def test_health_check_all_healthy(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert await composite.health_check() is True


async def test_health_check_false_if_any_unhealthy(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    handler_b.health_check = AsyncMock(return_value=False)
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert await composite.health_check() is False


async def test_get_dynamic_rules_returns_first_non_none(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    rules = {"rate_limit": 5}
    handler_a.get_dynamic_rules = AsyncMock(return_value=rules)
    handler_b.get_dynamic_rules = AsyncMock(return_value=None)
    composite = CompositeAgentHandler([handler_a, handler_b])
    result = await composite.get_dynamic_rules()
    assert result == rules


async def test_get_dynamic_rules_none_if_all_none(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert await composite.get_dynamic_rules() is None


async def test_send_event_continues_on_handler_failure(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    handler_a.send_event = AsyncMock(side_effect=RuntimeError("boom"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    event = {"event_type": "test"}
    await composite.send_event(event)
    handler_b.send_event.assert_awaited_once_with(event)


async def test_send_metric_continues_on_handler_failure(
    handler_a: AsyncMock, handler_b: AsyncMock
) -> None:
    handler_a.send_metric = AsyncMock(side_effect=RuntimeError("boom"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    metric = {"metric_type": "test"}
    await composite.send_metric(metric)
    handler_b.send_metric.assert_awaited_once_with(metric)


async def test_empty_handlers() -> None:
    composite = CompositeAgentHandler([])
    await composite.send_event({"event_type": "test"})
    await composite.send_metric({"metric_type": "test"})
    await composite.start()
    await composite.stop()
    assert await composite.health_check() is True
    assert await composite.get_dynamic_rules() is None


async def test_composite_filters_muted_events() -> None:
    from guard_core.core.events.event_types import EventFilter

    h = AsyncMock()
    h.send_event = AsyncMock()
    composite = CompositeAgentHandler(
        [h],
        event_filter=EventFilter(muted_event_types=frozenset({"penetration_attempt"})),
    )

    class _E:
        event_type = "penetration_attempt"

    await composite.send_event(_E())
    h.send_event.assert_not_called()

    class _E2:
        event_type = "ip_blocked"

    await composite.send_event(_E2())
    h.send_event.assert_called_once()


async def test_composite_filters_muted_metrics() -> None:
    from guard_core.core.events.event_types import EventFilter

    h = AsyncMock()
    h.send_metric = AsyncMock()
    composite = CompositeAgentHandler(
        [h],
        event_filter=EventFilter(muted_metric_types=frozenset({"response_time"})),
    )

    class _M:
        metric_type = "response_time"

    await composite.send_metric(_M())
    h.send_metric.assert_not_called()

    class _M2:
        metric_type = "request_count"

    await composite.send_metric(_M2())
    h.send_metric.assert_called_once()


async def test_composite_default_filter_allows_everything() -> None:
    h = AsyncMock()
    h.send_event = AsyncMock()
    composite = CompositeAgentHandler([h])

    class _E:
        event_type = "anything"

    await composite.send_event(_E())
    h.send_event.assert_called_once()


async def test_composite_event_without_event_type_passes_through() -> None:
    from guard_core.core.events.event_types import EventFilter

    h = AsyncMock()
    h.send_event = AsyncMock()
    composite = CompositeAgentHandler(
        [h],
        event_filter=EventFilter(muted_event_types=frozenset({"penetration_attempt"})),
    )
    await composite.send_event(object())
    h.send_event.assert_called_once()
