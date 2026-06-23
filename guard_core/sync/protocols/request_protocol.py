from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SyncGuardRequest(Protocol):
    """Framework-agnostic view of the inbound request the engine inspects.

    WHAT: the read-only surface (path, method, headers, client, body) every
    check reads, so the engine stays decoupled from any one web framework.
    WHEN: the adapter wraps each incoming request in this shape before the
    security pipeline runs; checks only ever see this protocol.
    HOW: the blocking mirror of ``GuardRequest``. Back each member with the
    underlying request object. Properties must be cheap, side-effect-free
    accessors; only ``body`` performs I/O and may be called more than once, so
    cache the bytes after the first read.
    """

    @property
    def url_path(self) -> str:
        """The request path, without scheme or host (e.g. ``/api/users``)."""
        ...

    @property
    def url_scheme(self) -> str:
        """The URL scheme, ``"http"`` or ``"https"``."""
        ...

    @property
    def url_full(self) -> str:
        """The fully reconstructed URL including scheme, host, path and query."""
        ...

    def url_replace_scheme(self, scheme: str) -> str:
        """Return the full URL with its scheme swapped for ``scheme``."""
        ...

    @property
    def method(self) -> str:
        """The HTTP method in upper case (e.g. ``GET``)."""
        ...

    @property
    def client_host(self) -> str | None:
        """The connecting peer's IP, or ``None`` when the client is unknown."""
        ...

    @property
    def headers(self) -> Mapping[str, str]:
        """The request headers as a case-insensitive mapping."""
        ...

    @property
    def query_params(self) -> Mapping[str, str]:
        """The parsed query-string parameters."""
        ...

    def body(self) -> bytes:
        """Return the raw request body. Safe to call repeatedly (cached)."""
        ...

    @property
    def state(self) -> Any:
        """Per-request scratch object for sharing data across checks."""
        ...

    @property
    def scope(self) -> dict[str, Any]:
        """The raw ASGI scope for adapters needing lower-level access."""
        ...
