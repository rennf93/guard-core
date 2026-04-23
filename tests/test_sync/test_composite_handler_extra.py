from unittest.mock import MagicMock

import pytest

from guard_core.sync.core.events.composite_handler import CompositeAgentHandler


@pytest.fixture
def handler_a():
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
def handler_b():
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


def test_start_continues_on_handler_failure(handler_a, handler_b):
    handler_a.start = MagicMock(side_effect=RuntimeError("start fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    composite.start()
    handler_b.start.assert_called_once()


def test_stop_continues_on_handler_failure(handler_a, handler_b):
    handler_a.stop = MagicMock(side_effect=RuntimeError("stop fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    composite.stop()
    handler_b.stop.assert_called_once()


def test_flush_buffer_continues_on_handler_failure(handler_a, handler_b):
    handler_a.flush_buffer = MagicMock(side_effect=RuntimeError("flush fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    composite.flush_buffer()
    handler_b.flush_buffer.assert_called_once()


def test_initialize_redis_continues_on_handler_failure(handler_a, handler_b):
    handler_a.initialize_redis = MagicMock(side_effect=RuntimeError("redis fail"))
    redis_handler = MagicMock()
    composite = CompositeAgentHandler([handler_a, handler_b])
    composite.initialize_redis(redis_handler)
    handler_b.initialize_redis.assert_called_once_with(redis_handler)


def test_health_check_continues_on_handler_failure(handler_a, handler_b):
    handler_a.health_check = MagicMock(side_effect=RuntimeError("health fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert composite.health_check() is False


def test_get_dynamic_rules_continues_on_handler_failure(handler_a, handler_b):
    handler_a.get_dynamic_rules = MagicMock(side_effect=RuntimeError("rules fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    result = composite.get_dynamic_rules()
    assert result is None


def test_get_dynamic_rules_returns_from_second_on_first_failure(handler_a, handler_b):
    handler_a.get_dynamic_rules = MagicMock(side_effect=RuntimeError("fail"))
    handler_b.get_dynamic_rules = MagicMock(return_value={"rule": "test"})
    composite = CompositeAgentHandler([handler_a, handler_b])
    result = composite.get_dynamic_rules()
    assert result == {"rule": "test"}


def test_health_check_true_with_single_handler():
    handler = MagicMock()
    handler.health_check = MagicMock(return_value=True)
    composite = CompositeAgentHandler([handler])
    assert composite.health_check() is True


def test_health_check_false_with_single_handler():
    handler = MagicMock()
    handler.health_check = MagicMock(return_value=False)
    composite = CompositeAgentHandler([handler])
    assert composite.health_check() is False
