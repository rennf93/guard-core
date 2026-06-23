from typing import Protocol, runtime_checkable

from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol


@runtime_checkable
class SyncGeoIPHandler(Protocol):
    """Resolver that maps an IP address to a country for geo-based rules.

    WHAT: wraps a geo database (or service) behind ``get_country`` plus the
    lifecycle needed to load and refresh it.
    WHEN: ``get_country`` is called during IP checks when country blocking or
    geo telemetry is enabled; ``initialize``/``refresh`` manage the dataset.
    HOW: the blocking mirror of ``GeoIPHandler``. Load lazily in ``initialize``
    and guard with ``is_initialized``; ``get_country`` must be cheap (it runs
    inline per request) and return ``None`` rather than raise when the IP can't
    be resolved.
    """

    @property
    def is_initialized(self) -> bool:
        """``True`` once the dataset is loaded and ``get_country`` is usable."""
        ...

    def initialize(self) -> None:
        """Load the geo dataset. Called once before lookups begin."""
        ...

    def initialize_redis(self, redis_handler: SyncRedisHandlerProtocol) -> None:
        """Attach the shared Redis backend for caching the dataset across workers."""
        ...

    def initialize_agent(self, agent_handler: SyncAgentHandlerProtocol) -> None:
        """Attach the agent so dataset-refresh failures can be reported."""
        ...

    def get_country(self, ip: str) -> str | None:
        """Return the ISO country code for ``ip``, or ``None`` if unknown."""
        ...

    def refresh(self) -> None:
        """Reload the dataset from source (periodic update)."""
        ...

    def close(self) -> None:
        """Release the dataset/file handles."""
        ...
