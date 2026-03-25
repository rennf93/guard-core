import logging
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from tests.test_sync.conftest import SyncMockGuardRequest


@pytest.fixture(autouse=True)
def cleanup_ratelimit_singleton() -> Generator[Any, Any, Any]:
    RateLimitManager._instance = None

    def custom_new(
        cls: type[RateLimitManager], config: SecurityConfig
    ) -> RateLimitManager:
        if cls._instance is None:
            cls._instance = object.__new__(cls)
            cls._instance.config = config
            cls._instance.request_timestamps = __import__("collections").defaultdict(
                lambda: __import__("collections").deque(maxlen=config.rate_limit * 2)
            )
            cls._instance.logger = logging.getLogger(__name__)
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
            cls._instance.rate_limit_script_sha = None
        cls._instance.config = config
        return cls._instance

    with (
        patch.object(RateLimitManager, "__new__", custom_new),
        patch(
            "guard_core.sync.handlers.ratelimit_handler.SecurityEvent", create=True
        ) as mock_event,
    ):
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield

    RateLimitManager._instance = None


def test_initialize_agent() -> None:
    RateLimitManager._instance = None

    config = SecurityConfig()
    manager = RateLimitManager(config)
    mock_agent = MagicMock()

    manager.initialize_agent(mock_agent)

    assert manager.agent_handler is mock_agent


def test_send_rate_limit_event_success() -> None:
    RateLimitManager._instance = None

    config = SecurityConfig(
        enable_rate_limiting=True, rate_limit=100, rate_limit_window=60
    )
    manager = RateLimitManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    mock_request = SyncMockGuardRequest(path="/api/test", method="GET")

    manager._send_rate_limit_event(
        request=mock_request, client_ip="192.168.1.100", request_count=150
    )

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "rate_limited"
    assert sent_event.ip_address == "192.168.1.100"
    assert sent_event.action_taken == "request_blocked"
    assert sent_event.reason == "Rate limit exceeded: 150 requests in 60s window"
    assert sent_event.endpoint == "/api/test"
    assert sent_event.method == "GET"
    assert sent_event.metadata["request_count"] == 150
    assert sent_event.metadata["rate_limit"] == 100
    assert sent_event.metadata["window"] == 60


def test_send_rate_limit_event_exception_handling(
    caplog: pytest.LogCaptureFixture,
) -> None:
    RateLimitManager._instance = None

    config = SecurityConfig(
        enable_rate_limiting=True, rate_limit=100, rate_limit_window=60
    )
    manager = RateLimitManager(config)
    mock_agent = MagicMock()
    mock_agent.send_event.side_effect = Exception("Network error")
    manager.agent_handler = mock_agent

    mock_request = SyncMockGuardRequest(path="/api/data", method="POST")

    caplog.set_level(logging.ERROR)

    manager._send_rate_limit_event(
        request=mock_request, client_ip="192.168.1.101", request_count=200
    )

    assert "Failed to send rate limit event to agent: Network error" in caplog.text


def test_check_rate_limit_agent_event_called() -> None:
    RateLimitManager._instance = None

    config = SecurityConfig(
        enable_rate_limiting=True,
        enable_redis=False,
        rate_limit=1,
        rate_limit_window=60,
        log_suspicious_level="WARNING",
    )
    manager = RateLimitManager(config)

    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    mock_request = SyncMockGuardRequest(path="/api/endpoint", method="GET")

    def mock_error_response(status_code: int, message: str) -> Any:
        return f"Error: {status_code} - {message}"

    with (
        patch("guard_core.sync.handlers.ratelimit_handler.log_activity"),
        patch.object(manager, "_send_rate_limit_event") as mock_send_event,
    ):
        result1 = manager.check_rate_limit(
            request=mock_request,
            client_ip="192.168.1.100",
            create_error_response=mock_error_response,
        )
        assert result1 is None

        result2 = manager.check_rate_limit(
            request=mock_request,
            client_ip="192.168.1.100",
            create_error_response=mock_error_response,
        )

        assert result2 == "Error: 429 - Too many requests"

        mock_send_event.assert_called_once_with(mock_request, "192.168.1.100", 2)


def test_check_rate_limit_redis_path_with_agent() -> None:
    RateLimitManager._instance = None

    config = SecurityConfig(
        enable_rate_limiting=True,
        enable_redis=True,
        rate_limit=10,
        rate_limit_window=60,
        log_suspicious_level="WARNING",
    )
    manager = RateLimitManager(config)

    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    class MockRedisConnection:
        def __init__(self) -> None:
            self.evalsha = MagicMock(return_value=15)

        def __enter__(self) -> Any:
            return self

        def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
            return None

    mock_redis = MagicMock()
    mock_redis.get_connection = MagicMock(return_value=MockRedisConnection())
    manager.redis_handler = mock_redis
    manager.rate_limit_script_sha = "test_sha"

    mock_request = SyncMockGuardRequest(path="/api/test", method="POST")

    def mock_error_response(status_code: int, message: str) -> Any:
        return {"status": status_code, "message": message}

    with patch("guard_core.sync.handlers.ratelimit_handler.log_activity"):
        result = manager.check_rate_limit(
            request=mock_request,
            client_ip="192.168.1.200",
            create_error_response=mock_error_response,
        )

        assert result == {"status": 429, "message": "Too many requests"}

        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        assert sent_event.event_type == "rate_limited"
        assert sent_event.ip_address == "192.168.1.200"
        assert sent_event.action_taken == "request_blocked"
        assert "Rate limit exceeded" in sent_event.reason
        assert sent_event.endpoint == "/api/test"
        assert sent_event.method == "POST"
        assert sent_event.metadata["request_count"] == 15
