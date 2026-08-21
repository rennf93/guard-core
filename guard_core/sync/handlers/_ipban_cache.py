import ipaddress
from collections.abc import Callable
from typing import Any

from cachetools import TTLCache

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class _ObservableTTLCache(TTLCache):
    def __init__(
        self,
        maxsize: int,
        ttl: float,
        on_evict: Callable[[], None],
    ) -> None:
        super().__init__(maxsize=maxsize, ttl=ttl)
        self._on_evict = on_evict

    def popitem(self) -> tuple[Any, Any]:
        item = super().popitem()
        self._on_evict()
        return item
