from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class GuardRequest(Protocol):
    """Framework-agnostic view of the inbound request the engine inspects.

    WHAT: the read-only surface (path, method, headers, client, body) every
    check reads, so the engine stays decoupled from any one web framework.
    WHEN: the adapter wraps each incoming request in this shape before the
    security pipeline runs; checks only ever see this protocol.
    HOW: back each member with the underlying request object. Properties must
    be cheap, side-effect-free accessors; only ``body`` performs I/O and may be
    called more than once, so cache the bytes after the first read.
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

    async def body(self) -> bytes:
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


@runtime_checkable
class BoundedBodyReader(Protocol):
    """Optional capability: read a size-capped prefix of the request body.

    WHAT: lets a caller read at most ``max_bytes`` of the body without
    buffering the rest, for requests whose total size is not known upfront.
    WHEN: consulted when the request has no usable ``Content-Length`` (for
    example a chunked transfer-encoding), so the body can still be inspected
    up to a bound instead of being skipped or read in full.
    HOW: adapters implement this alongside ``GuardRequest`` by reading from
    their underlying stream and stopping at ``max_bytes``. It is a separate,
    optional protocol: an adapter that only implements ``GuardRequest`` is
    still fully valid, and callers must treat the absence of this capability
    as "cannot bound the read" and fall back accordingly rather than reading
    the body in full.

    DETECTION LIMIT: only the returned prefix is ever scanned. A payload
    placed after the first ``max_bytes`` of the body, or a signature split
    across the ``max_bytes`` boundary, is not detected. This is the
    memory/detection tradeoff bounded-memory scanning makes on purpose; it
    is not equivalent to scanning the full body and must not be presented
    as such.

    MEMORY OBLIGATION (see GHSA-xv6g-49vj-7w9c): the caller defensively
    slices the returned bytes to ``max_bytes``, but that slice only trims
    what the implementation already returned; it cannot stop an
    implementation from reading or buffering more than ``max_bytes``
    internally before returning. Implementations MUST NOT buffer more than
    ``max_bytes`` while producing the prefix -- guard-core has no way to
    enforce this from the caller side.
    """

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        """Return up to ``max_bytes`` of the body, read from its start."""
        ...
