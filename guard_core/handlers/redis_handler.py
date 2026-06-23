import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import ConnectionError

from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig


class RedisManager:
    _instance = None
    _redis: Redis | None = None
    _connection_lock = asyncio.Lock()
    _closed = False
    config: SecurityConfig
    logger: logging.Logger
    agent_handler: Any = None

    def __new__(cls: type["RedisManager"], config: SecurityConfig) -> "RedisManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.logger = logging.getLogger("guard_core.handlers.redis")
            cls._instance.agent_handler = None
        cls._instance.config = config
        cls._instance._closed = False
        return cls._instance

    async def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    async def _send_redis_event(
        self, event_type: str, action_taken: str, reason: str, **kwargs: Any
    ) -> None:
        if not self.agent_handler:
            return

        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address="system",
                action_taken=action_taken,
                reason=reason,
                metadata=kwargs,
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send Redis event to agent: {e}")

    async def initialize(self) -> None:
        if not self.config.enable_redis:
            self._redis = None
            return

        self._closed = False

        async with self._connection_lock:
            try:
                if self.config.redis_url is not None:
                    self._redis = Redis.from_url(
                        self.config.redis_url, decode_responses=True
                    )
                    if self._redis is not None:
                        await self._redis.ping()
                        self.logger.info("Redis connection established")

                        await self._send_redis_event(
                            event_type="redis_connection",
                            action_taken="connection_established",
                            reason="Redis connection successfully established",
                            redis_url=self.config.redis_url,
                        )
                else:
                    self.logger.warning("Redis URL is None, skipping connection")

            except Exception as e:
                self.logger.error(f"Redis connection failed: {str(e)}")

                await self._send_redis_event(
                    event_type="redis_error",
                    action_taken="connection_failed",
                    reason=f"Redis connection failed: {str(e)}",
                    redis_url=self.config.redis_url,
                    error_type="connection_error",
                )

                self._redis = None
                raise GuardRedisError(503, "Redis connection failed") from e

    async def close(self) -> None:
        if self._redis:
            await self._redis.aclose()
            self._redis = None
            self.logger.info("Redis connection closed")

            await self._send_redis_event(
                event_type="redis_connection",
                action_taken="connection_closed",
                reason="Redis connection closed gracefully",
            )
        self._closed = True

    @asynccontextmanager
    async def get_connection(self) -> AsyncIterator[Redis]:
        try:
            if self._closed:
                await self._send_redis_event(
                    event_type="redis_error",
                    action_taken="operation_failed",
                    reason="Attempted to use closed Redis connection",
                    error_type="connection_closed",
                )
                raise GuardRedisError(503, "Redis connection closed")

            if not self._redis:
                await self.initialize()

            if self._redis is None:
                await self._send_redis_event(
                    event_type="redis_error",
                    action_taken="operation_failed",
                    reason="Redis connection is None after initialization",
                    error_type="initialization_failed",
                )
                raise GuardRedisError(503, "Redis connection failed")

            yield self._redis
        except (ConnectionError, AttributeError) as e:
            self.logger.error(f"Redis operation failed: {str(e)}")

            await self._send_redis_event(
                event_type="redis_error",
                action_taken="operation_failed",
                reason=f"Redis operation failed: {str(e)}",
                error_type="operation_error",
            )

            raise GuardRedisError(503, "Redis connection failed") from e

    async def safe_operation(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        if not self.config.enable_redis:
            return None

        try:
            async with self.get_connection() as conn:
                return await func(conn, *args, **kwargs)
        except Exception as e:
            self.logger.error(f"Redis operation failed: {str(e)}")

            await self._send_redis_event(
                event_type="redis_error",
                action_taken="safe_operation_failed",
                reason=f"Redis safe operation failed: {str(e)}",
                error_type="safe_operation_error",
                function_name=getattr(func, "__name__", "unknown"),
            )

            raise GuardRedisError(503, "Redis operation failed") from e

    async def get_key(self, namespace: str, key: str) -> Any:
        if not self.config.enable_redis:
            return None

        async def _get(conn: Redis) -> Any:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            return await conn.get(full_key)

        return await self.safe_operation(_get)

    async def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool | None:
        if not self.config.enable_redis:
            return None

        async def _set(conn: Redis) -> bool:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            if ttl:
                return bool(await conn.set(full_key, value, ex=ttl))
            return bool(await conn.set(full_key, value))

        result = await self.safe_operation(_set)
        return False if result is None else bool(result)

    async def incr(
        self, namespace: str, key: str, ttl: int | None = None
    ) -> int | None:
        if not self.config.enable_redis:
            return None

        async def _incr(conn: Redis) -> int:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            async with conn.pipeline() as pipe:
                await pipe.incr(full_key)
                if ttl:
                    await pipe.expire(full_key, ttl)
                result = await pipe.execute()
                return int(result[0]) if result else 0

        result = await self.safe_operation(_incr)
        return int(result) if result is not None else 0

    async def exists(self, namespace: str, key: str) -> bool | None:
        if not self.config.enable_redis:
            return None

        async def _exists(conn: Redis) -> bool:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            return bool(await conn.exists(full_key))

        result = await self.safe_operation(_exists)
        return False if result is None else bool(result)

    async def delete(self, namespace: str, key: str) -> int | None:
        if not self.config.enable_redis:
            return None

        async def _delete(conn: Redis) -> int:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            delete_result = await conn.delete(full_key)
            return int(delete_result) if delete_result is not None else 0

        result = await self.safe_operation(_delete)
        return int(result) if result is not None else 0

    async def keys(self, pattern: str) -> list[str] | None:
        if not self.config.enable_redis:
            return None

        async def _keys(conn: Redis) -> list[str]:
            full_pattern = f"{self.config.redis_prefix}{pattern}"
            keys = await conn.keys(full_pattern)
            return [str(k) for k in keys] if keys else []

        result = await self.safe_operation(_keys)
        return result if result is not None else []

    async def delete_pattern(self, pattern: str) -> int | None:
        if not self.config.enable_redis:
            return None

        async def _delete_pattern(conn: Redis) -> int:
            full_pattern = f"{self.config.redis_prefix}{pattern}"
            keys = await conn.keys(full_pattern)
            if not keys:
                return 0
            result = await conn.delete(*keys)
            return int(result) if result is not None else 0

        result = await self.safe_operation(_delete_pattern)
        return int(result) if result is not None else 0


redis_handler = RedisManager
