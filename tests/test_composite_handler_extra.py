from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.events.composite_handler import CompositeAgentHandler


@pytest.fixture
def handler_a():
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
def handler_b():
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


async def test_start_continues_on_handler_failure(handler_a, handler_b):
    handler_a.start = AsyncMock(side_effect=RuntimeError("start fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    await composite.start()
    handler_b.start.assert_awaited_once()


async def test_stop_continues_on_handler_failure(handler_a, handler_b):
    handler_a.stop = AsyncMock(side_effect=RuntimeError("stop fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    await composite.stop()
    handler_b.stop.assert_awaited_once()


async def test_flush_buffer_continues_on_handler_failure(handler_a, handler_b):
    handler_a.flush_buffer = AsyncMock(side_effect=RuntimeError("flush fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    await composite.flush_buffer()
    handler_b.flush_buffer.assert_awaited_once()


async def test_initialize_redis_continues_on_handler_failure(handler_a, handler_b):
    handler_a.initialize_redis = AsyncMock(side_effect=RuntimeError("redis fail"))
    redis_handler = MagicMock()
    composite = CompositeAgentHandler([handler_a, handler_b])
    await composite.initialize_redis(redis_handler)
    handler_b.initialize_redis.assert_awaited_once_with(redis_handler)


async def test_health_check_continues_on_handler_failure(handler_a, handler_b):
    handler_a.health_check = AsyncMock(side_effect=RuntimeError("health fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert await composite.health_check() is False


async def test_get_dynamic_rules_continues_on_handler_failure(handler_a, handler_b):
    handler_a.get_dynamic_rules = AsyncMock(side_effect=RuntimeError("rules fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    result = await composite.get_dynamic_rules()
    assert result is None


async def test_get_dynamic_rules_returns_from_second_on_first_failure(
    handler_a, handler_b
):
    handler_a.get_dynamic_rules = AsyncMock(side_effect=RuntimeError("fail"))
    handler_b.get_dynamic_rules = AsyncMock(return_value={"rule": "test"})
    composite = CompositeAgentHandler([handler_a, handler_b])
    result = await composite.get_dynamic_rules()
    assert result == {"rule": "test"}


async def test_health_check_true_with_single_handler():
    handler = AsyncMock()
    handler.health_check = AsyncMock(return_value=True)
    composite = CompositeAgentHandler([handler])
    assert await composite.health_check() is True


async def test_health_check_false_with_single_handler():
    handler = AsyncMock()
    handler.health_check = AsyncMock(return_value=False)
    composite = CompositeAgentHandler([handler])
    assert await composite.health_check() is False
