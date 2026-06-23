import json
from typing import Any

from guard_core.protocols.redis_protocol import RedisHandlerProtocol


class InMemoryCloudIpStore:
    def __init__(self) -> None:
        self._data: dict[str, set[str]] = {}

    async def get(self, provider: str) -> set[str] | None:
        ranges = self._data.get(provider)
        if ranges is None:
            return None
        return set(ranges)

    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None:
        self._data[provider] = set(ranges)

    async def clear(self) -> None:
        self._data.clear()


class RedisCloudIpStore:
    def __init__(
        self,
        redis_handler: RedisHandlerProtocol,
        key_prefix: str = "cloud_ip_v2",
    ) -> None:
        self._redis = redis_handler
        self._prefix = key_prefix

    async def get(self, provider: str) -> set[str] | None:
        raw: Any = await self._redis.get_key(self._prefix, provider)
        if raw is None:
            return None
        try:
            decoded = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(decoded, list):
            return None
        return {str(item) for item in decoded}

    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None:
        payload = json.dumps(sorted(ranges))
        await self._redis.set_key(self._prefix, provider, payload, ttl=ttl)

    async def clear(self) -> None:
        keys: list[str] | None = await self._redis.keys(f"{self._prefix}:*")
        if not keys:
            return
        for key in keys:
            _, _, provider = key.partition(f"{self._prefix}:")
            if provider:
                await self._redis.delete(self._prefix, provider)
