import asyncio
import os
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from redis.exceptions import ConnectionError

from guard_core.exceptions import GuardRedisError
from guard_core.handlers.redis_handler import redis_handler
from guard_core.models import SecurityConfig

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))


@pytest.mark.asyncio
async def test_redis_basic_operations(security_config_redis: SecurityConfig) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    await handler.set_key("test", "key1", "value1")
    value = await handler.get_key("test", "key1")
    assert value == "value1"

    exists = await handler.exists("test", "key1")
    assert exists is True

    await handler.delete("test", "key1")
    exists = await handler.exists("test", "key1")
    assert exists is False

    await handler.close()


@pytest.mark.asyncio
async def test_redis_disabled(security_config: SecurityConfig) -> None:
    handler = redis_handler(security_config)
    await handler.initialize()

    assert not security_config.enable_redis
    assert handler._redis is None
    result = await handler.set_key("test", "key1", "value1")
    assert result is None
    value = await handler.get_key("test", "key1")
    assert value is None


@pytest.mark.asyncio
async def test_redis_error_handling(security_config_redis: SecurityConfig) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    async def _fail_operation(conn: Any) -> None:
        raise ConnectionError("Test connection error")

    with pytest.raises(GuardRedisError) as exc_info:
        await handler.safe_operation(_fail_operation)
    assert exc_info.value.status_code == 503

    await handler.close()


@pytest.mark.asyncio
async def test_redis_ttl_operations(security_config_redis: SecurityConfig) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    await handler.set_key("test", "ttl_key", "value", ttl=1)
    value = await handler.get_key("test", "ttl_key")
    assert value == "value"

    await asyncio.sleep(1.1)
    value = await handler.get_key("test", "ttl_key")
    assert value is None

    await handler.close()


@pytest.mark.asyncio
async def test_redis_increment_operations(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    async with handler.get_connection() as conn:
        prefix = security_config_redis.redis_prefix
        await conn.delete(f"{prefix}test:counter")
        await conn.delete(f"{prefix}test:ttl_counter")

    value = await handler.incr("test", "counter")
    assert value == 1
    value = await handler.incr("test", "counter")
    assert value == 2

    value = await handler.incr("test", "ttl_counter", ttl=1)
    assert value == 1
    await asyncio.sleep(1.1)
    exists = await handler.exists("test", "ttl_counter")
    assert not exists

    await handler.close()


@pytest.mark.asyncio
async def test_redis_connection_context_get_error(
    security_config_redis: SecurityConfig, monkeypatch: Any
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    async def mock_get(*args: Any, **kwargs: Any) -> None:
        raise ConnectionError("Test connection error on get")

    with pytest.raises(GuardRedisError) as exc_info:
        async with handler.get_connection() as conn:
            monkeypatch.setattr(conn, "get", mock_get)
            await conn.get("test:key")

    assert exc_info.value.status_code == 503

    await handler.close()


@pytest.mark.asyncio
async def test_redis_connection_failures(security_config_redis: SecurityConfig) -> None:
    bad_config = SecurityConfig(
        **{
            **security_config_redis.model_dump(),
            "redis_url": "redis://nonexistent:6379",
        }
    )
    handler = redis_handler(bad_config)
    with pytest.raises(GuardRedisError) as exc_info:
        await handler.initialize()
    assert exc_info.value.status_code == 503
    assert handler._redis is None

    handler = redis_handler(security_config_redis)
    await handler.initialize()

    await handler.close()
    with pytest.raises(GuardRedisError) as exc_info:
        await handler.get_key("test", "key")
    assert exc_info.value.status_code == 503

    handler._redis = None
    with pytest.raises(GuardRedisError) as exc_info:
        await handler.safe_operation(lambda conn: conn.get("test:key"))
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_redis_disabled_operations(security_config_redis: SecurityConfig) -> None:
    security_config_redis.enable_redis = False
    handler = redis_handler(security_config_redis)

    assert await handler.get_key("test", "key") is None
    assert await handler.set_key("test", "key", "value") is None
    assert await handler.incr("test", "counter") is None
    assert await handler.exists("test", "key") is None
    assert await handler.delete("test", "key") is None


@pytest.mark.asyncio
async def test_redis_failed_initialization_operations(
    security_config_redis: SecurityConfig,
) -> None:
    bad_config = SecurityConfig(
        **{**security_config_redis.model_dump(), "redis_url": "redis://invalid:6379"}
    )
    handler = redis_handler(bad_config)

    with pytest.raises(GuardRedisError) as exc_info:
        await handler.get_key("test", "key")
    assert exc_info.value.status_code == 503

    with pytest.raises(GuardRedisError) as exc_info:
        await handler.set_key("test", "key", "value")
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_redis_url_none(security_config_redis: SecurityConfig) -> None:
    security_config_redis.redis_url = None

    handler = redis_handler(security_config_redis)

    with patch("logging.Logger.warning") as mock_warning:
        await handler.initialize()
        mock_warning.assert_called_once_with("Redis URL is None, skipping connection")
        assert handler._redis is None


@pytest.mark.asyncio
async def test_safe_operation_redis_disabled(security_config: SecurityConfig) -> None:
    handler = redis_handler(security_config)

    mock_func = AsyncMock()
    result = await handler.safe_operation(mock_func)

    assert result is None
    mock_func.assert_not_called()


@pytest.mark.asyncio
async def test_connection_context_redis_none(
    security_config_redis: SecurityConfig, monkeypatch: Any
) -> None:
    handler = redis_handler(security_config_redis)

    initialize_called = False

    async def mocked_initialize() -> None:
        nonlocal initialize_called
        initialize_called = True

    monkeypatch.setattr(handler, "initialize", mocked_initialize)

    handler._closed = False
    handler._redis = None

    with pytest.raises(GuardRedisError) as exc_info:
        await handler.get_connection().__aenter__()

    assert initialize_called, "initialize() was not called"
    assert exc_info.value.status_code == 503
    assert "Redis connection failed" in exc_info.value.detail


@pytest.mark.asyncio
async def test_redis_keys_and_delete_pattern_with_redis_disabled() -> None:
    config = SecurityConfig(enable_redis=False)
    handler = redis_handler(config)

    keys_result = await handler.keys("*")
    assert keys_result is None

    delete_result = await handler.delete_pattern("*")
    assert delete_result is None


async def test_initialize_logs_warning_when_redis_url_is_none() -> None:
    from unittest.mock import patch

    from guard_core.handlers.redis_handler import RedisManager
    from guard_core.models import SecurityConfig

    RedisManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url=None)
    manager = RedisManager(config)
    with patch.object(manager.logger, "warning") as mock_warn:
        await manager.initialize()
    mock_warn.assert_called()
    RedisManager._instance = None


async def test_close_noop_when_redis_not_connected() -> None:
    from guard_core.handlers.redis_handler import RedisManager
    from guard_core.models import SecurityConfig

    RedisManager._instance = None
    manager = RedisManager(SecurityConfig(enable_redis=True))
    manager._redis = None
    await manager.close()
    assert manager._closed is True
    RedisManager._instance = None


async def test_initialize_when_from_url_returns_none_skips_ping() -> None:
    from unittest.mock import patch

    from guard_core.handlers.redis_handler import RedisManager
    from guard_core.models import SecurityConfig

    RedisManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    manager = RedisManager(config)
    with patch("guard_core.handlers.redis_handler.Redis.from_url", return_value=None):
        await manager.initialize()
    assert manager._redis is None
    RedisManager._instance = None
