from typing import Any, Protocol, runtime_checkable

from typing_extensions import AsyncContextManager


@runtime_checkable
class RedisHandlerProtocol(Protocol):
    """Storage backend the engine uses for all shared, cross-worker state.

    WHAT: a namespaced async key-value store (rate-limit counters, IP bans,
    cloud-IP ranges, behavioral tallies) keyed by ``(namespace, key)``.
    WHEN: every handler that persists state resolves it through this protocol;
    ``initialize`` runs once at startup before any read/write.
    HOW: implement a thin adapter over your Redis client. Reads return ``None``
    on a miss (never raise for absent keys); keep calls non-blocking on the
    request hot path. All TTLs are expressed in seconds.
    """

    async def get_key(self, namespace: str, key: str) -> Any:
        """Return the value stored at ``namespace:key``, or ``None`` if absent."""
        ...

    async def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool | None:
        """Store ``value`` at ``namespace:key``, expiring after ``ttl`` seconds.

        ``ttl=None`` persists with no expiry. Returns the backend's set result
        (truthy on success) or ``None`` when the backend reports nothing.
        """
        ...

    async def delete(self, namespace: str, key: str) -> int | None:
        """Delete ``namespace:key``; return the number of keys removed (0 if none)."""
        ...

    async def keys(self, pattern: str) -> list[str] | None:
        """Return keys matching ``pattern``, or ``None`` when none can be listed."""
        ...

    async def initialize(self) -> None:
        """Open the connection/pool. Called once at startup before any access."""
        ...

    def get_connection(self) -> AsyncContextManager[Any]:
        """Yield a raw client for operations not covered by this protocol."""
        ...
