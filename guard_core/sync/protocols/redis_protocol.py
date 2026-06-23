from typing import Any, Protocol, runtime_checkable

from typing_extensions import ContextManager


@runtime_checkable
class SyncRedisHandlerProtocol(Protocol):
    """Storage backend the engine uses for all shared, cross-worker state.

    WHAT: a namespaced key-value store (rate-limit counters, IP bans, cloud-IP
    ranges, behavioral tallies) keyed by ``(namespace, key)``.
    WHEN: every handler that persists state resolves it through this protocol;
    ``initialize`` runs once at startup before any read/write.
    HOW: implement a thin adapter over your Redis client. This is the blocking
    mirror of ``RedisHandlerProtocol``: calls are synchronous and
    ``get_connection`` yields a ``ContextManager``. Reads return ``None`` on a
    miss (never raise for absent keys); keep calls fast on the request hot
    path. All TTLs are expressed in seconds.
    """

    def get_key(self, namespace: str, key: str) -> Any:
        """Return the value stored at ``namespace:key``, or ``None`` if absent."""
        ...

    def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool | None:
        """Store ``value`` at ``namespace:key``, expiring after ``ttl`` seconds.

        ``ttl=None`` persists with no expiry. Returns the backend's set result
        (truthy on success) or ``None`` when the backend reports nothing.
        """
        ...

    def delete(self, namespace: str, key: str) -> int | None:
        """Delete ``namespace:key``; return the number of keys removed (0 if none)."""
        ...

    def keys(self, pattern: str) -> list[str] | None:
        """Return keys matching ``pattern``, or ``None`` when none can be listed."""
        ...

    def initialize(self) -> None:
        """Open the connection/pool. Called once at startup before any access."""
        ...

    def get_connection(self) -> ContextManager[Any]:
        """Yield a raw client for operations not covered by this protocol."""
        ...
