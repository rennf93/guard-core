from unittest.mock import MagicMock, patch

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.redis_handler import redis_handler


def test_connection_kwargs_from_config() -> None:
    config = SecurityConfig(
        redis_url="redis://localhost:6379",
        redis_socket_timeout=0.5,
        redis_socket_connect_timeout=0.25,
        redis_health_check_interval=15,
        redis_max_connections=20,
        redis_retries=2,
    )
    handler = redis_handler(config)

    kwargs = handler._connection_kwargs()

    assert kwargs["socket_timeout"] == 0.5
    assert kwargs["socket_connect_timeout"] == 0.25
    assert kwargs["health_check_interval"] == 15
    assert kwargs["max_connections"] == 20
    assert "retry" in kwargs
    assert kwargs["retry_on_error"]


def test_connection_kwargs_retries_disabled() -> None:
    config = SecurityConfig(
        redis_url="redis://localhost:6379",
        redis_retries=0,
        redis_max_connections=None,
    )
    handler = redis_handler(config)

    kwargs = handler._connection_kwargs()

    assert "retry" not in kwargs
    assert "retry_on_error" not in kwargs
    assert "max_connections" not in kwargs


def test_initialize_passes_connection_kwargs() -> None:
    config = SecurityConfig(
        redis_url="redis://localhost:6379",
        redis_socket_timeout=0.5,
        redis_socket_connect_timeout=0.25,
    )
    handler = redis_handler(config)

    with patch(
        "guard_core.sync.handlers.redis_handler.Redis.from_url"
    ) as mock_from_url:
        mock_from_url.return_value = MagicMock()
        handler.initialize()

    _, kwargs = mock_from_url.call_args
    assert kwargs["decode_responses"] is True
    assert kwargs["socket_timeout"] == 0.5
    assert kwargs["socket_connect_timeout"] == 0.25
    handler.close()
