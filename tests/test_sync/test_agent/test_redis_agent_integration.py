import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager


@pytest.fixture(autouse=True)
def patch_security_event() -> Any:
    with patch(
        "guard_core.sync.handlers.redis_handler.SecurityEvent", create=True
    ) as mock_event:
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield


def test_initialize_agent() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()

    manager.initialize_agent(mock_agent)

    assert manager.agent_handler is mock_agent


def test_send_redis_event_no_agent() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    manager.agent_handler = None

    manager._send_redis_event(
        event_type="redis_connection",
        action_taken="test_action",
        reason="test reason",
    )


def test_send_redis_event_success() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    manager._send_redis_event(
        event_type="redis_connection",
        action_taken="connection_established",
        reason="Redis connection successfully established",
        redis_url="redis://localhost",
        extra_data="test",
    )

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "redis_connection"
    assert sent_event.ip_address == "system"
    assert sent_event.action_taken == "connection_established"
    assert sent_event.reason == "Redis connection successfully established"
    assert sent_event.metadata["redis_url"] == "redis://localhost"
    assert sent_event.metadata["extra_data"] == "test"


def test_send_redis_event_exception_handling(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()
    mock_agent.send_event.side_effect = Exception("Network error")
    manager.agent_handler = mock_agent

    caplog.set_level(logging.ERROR, logger="fastapi_guard.handlers.redis")

    manager._send_redis_event(
        event_type="redis_error",
        action_taken="operation_failed",
        reason="Test failure",
    )

    assert "Failed to send Redis event to agent: Network error" in caplog.text


def test_close_with_agent() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    mock_redis = MagicMock()
    mock_redis.close = MagicMock()
    manager._redis = mock_redis

    manager.close()

    mock_redis.close.assert_called_once()
    assert manager._redis is None


def test_get_connection_closed_error_with_agent() -> None:
    from guard_core.exceptions import GuardRedisError

    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent
    manager._closed = True

    with pytest.raises(GuardRedisError) as exc_info:
        with manager.get_connection():
            pass  # pragma: no cover

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Redis connection closed"

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "redis_error"
    assert sent_event.action_taken == "operation_failed"
    assert sent_event.reason == "Attempted to use closed Redis connection"
    assert sent_event.metadata["error_type"] == "connection_closed"


def test_get_connection_initialization_failure_with_agent() -> None:
    from guard_core.exceptions import GuardRedisError

    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent
    manager._redis = None

    with pytest.raises(GuardRedisError) as exc_info:
        with manager.get_connection():
            pass  # pragma: no cover

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Redis connection failed"

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "redis_error"
    assert sent_event.action_taken == "operation_failed"
    assert sent_event.reason == "Redis connection is None after initialization"
    assert sent_event.metadata["error_type"] == "initialization_failed"


def test_safe_operation_failure_with_agent() -> None:
    from guard_core.exceptions import GuardRedisError

    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    def failing_func(conn: Any) -> None:
        raise Exception("Operation failed")  # pragma: no cover

    failing_func.__name__ = "failing_func"

    with pytest.raises(GuardRedisError) as exc_info:
        manager.safe_operation(failing_func)

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Redis operation failed"


def test_safe_operation_error_inside_context() -> None:
    from guard_core.exceptions import GuardRedisError

    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    mock_redis = MagicMock()
    manager._redis = mock_redis

    def failing_operation(conn: Any) -> None:
        raise ValueError("Operation error inside context")

    failing_operation.__name__ = "failing_operation"

    with pytest.raises(GuardRedisError) as exc_info:
        manager.safe_operation(failing_operation)

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Redis operation failed"

    calls = mock_agent.send_event.call_args_list
    assert len(calls) > 0

    found = False
    for call in calls:
        event = call[0][0]
        if event.action_taken == "safe_operation_failed":
            found = True
            assert event.event_type == "redis_error"
            assert "Operation error inside context" in event.reason
            assert event.metadata["error_type"] == "safe_operation_error"
            assert event.metadata["function_name"] == "failing_operation"
            break

    assert found, "safe_operation_failed event not found"
