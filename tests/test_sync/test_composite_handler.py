from unittest.mock import MagicMock

import pytest

from guard_core.sync.core.events.composite_handler import CompositeAgentHandler


@pytest.fixture
def handler_a() -> MagicMock:
    handler = MagicMock()
    handler.send_event = MagicMock()
    handler.send_metric = MagicMock()
    handler.start = MagicMock()
    handler.stop = MagicMock()
    handler.flush_buffer = MagicMock()
    handler.health_check = MagicMock(return_value=True)
    handler.get_dynamic_rules = MagicMock(return_value=None)
    handler.initialize_redis = MagicMock()
    return handler


@pytest.fixture
def handler_b() -> MagicMock:
    handler = MagicMock()
    handler.send_event = MagicMock()
    handler.send_metric = MagicMock()
    handler.start = MagicMock()
    handler.stop = MagicMock()
    handler.flush_buffer = MagicMock()
    handler.health_check = MagicMock(return_value=True)
    handler.get_dynamic_rules = MagicMock(return_value=None)
    handler.initialize_redis = MagicMock()
    return handler


def test_fanout_send_event(handler_a: MagicMock, handler_b: MagicMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    event = {"event_type": "penetration_attempt", "ip": "1.2.3.4"}
    composite.send_event(event)
    handler_a.send_event.assert_called_once_with(event)
    handler_b.send_event.assert_called_once_with(event)


def test_fanout_send_metric(handler_a: MagicMock, handler_b: MagicMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    metric = {"metric_type": "response_time", "value": 0.5}
    composite.send_metric(metric)
    handler_a.send_metric.assert_called_once_with(metric)
    handler_b.send_metric.assert_called_once_with(metric)


def test_delegates_start_stop(handler_a: MagicMock, handler_b: MagicMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    composite.start()
    handler_a.start.assert_called_once()
    handler_b.start.assert_called_once()
    composite.stop()
    handler_a.stop.assert_called_once()
    handler_b.stop.assert_called_once()


def test_delegates_flush_buffer(handler_a: MagicMock, handler_b: MagicMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    composite.flush_buffer()
    handler_a.flush_buffer.assert_called_once()
    handler_b.flush_buffer.assert_called_once()


def test_delegates_initialize_redis(handler_a: MagicMock, handler_b: MagicMock) -> None:
    redis_handler = MagicMock()
    composite = CompositeAgentHandler([handler_a, handler_b])
    composite.initialize_redis(redis_handler)
    handler_a.initialize_redis.assert_called_once_with(redis_handler)
    handler_b.initialize_redis.assert_called_once_with(redis_handler)


def test_health_check_all_healthy(handler_a: MagicMock, handler_b: MagicMock) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert composite.health_check() is True


def test_health_check_false_if_any_unhealthy(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_b.health_check = MagicMock(return_value=False)
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert composite.health_check() is False


def test_get_dynamic_rules_returns_first_non_none(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    rules = {"rate_limit": 5}
    handler_a.get_dynamic_rules = MagicMock(return_value=rules)
    handler_b.get_dynamic_rules = MagicMock(return_value=None)
    composite = CompositeAgentHandler([handler_a, handler_b])
    result = composite.get_dynamic_rules()
    assert result == rules


def test_get_dynamic_rules_none_if_all_none(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert composite.get_dynamic_rules() is None


def test_send_event_continues_on_handler_failure(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_a.send_event = MagicMock(side_effect=RuntimeError("boom"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    event = {"event_type": "test"}
    composite.send_event(event)
    handler_b.send_event.assert_called_once_with(event)


def test_send_metric_continues_on_handler_failure(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_a.send_metric = MagicMock(side_effect=RuntimeError("boom"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    metric = {"metric_type": "test"}
    composite.send_metric(metric)
    handler_b.send_metric.assert_called_once_with(metric)


def test_empty_handlers() -> None:
    composite = CompositeAgentHandler([])
    composite.send_event({"event_type": "test"})
    composite.send_metric({"metric_type": "test"})
    composite.start()
    composite.stop()
    assert composite.health_check() is True
    assert composite.get_dynamic_rules() is None
