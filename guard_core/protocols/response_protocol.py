from collections.abc import MutableMapping
from typing import Protocol, runtime_checkable


@runtime_checkable
class GuardResponse(Protocol):
    """Framework-agnostic view of a response the engine returns or inspects.

    WHAT: the minimal surface (status, headers, body) the engine reads from a
    block/redirect response and the adapter renders back to the framework.
    WHEN: produced by ``GuardResponseFactory`` when a check denies a request,
    and read by the adapter to emit the real framework response.
    HOW: wrap the framework's response object; ``headers`` is mutable so the
    engine can attach security headers before the response is sent.
    """

    @property
    def status_code(self) -> int:
        """The HTTP status code."""
        ...

    @property
    def headers(self) -> MutableMapping[str, str]:
        """The response headers; mutable so the engine can add/override them."""
        ...

    @property
    def body(self) -> bytes | None:
        """The response body, or ``None`` when there is no body."""
        ...


@runtime_checkable
class GuardResponseFactory(Protocol):
    """Builds the responses the engine returns when a check denies a request.

    WHAT: the seam that lets the engine emit error/redirect responses without
    knowing the concrete framework response type.
    WHEN: called by checks at the moment of a block to construct the outgoing
    ``GuardResponse``.
    HOW: return objects satisfying ``GuardResponse``; keep construction pure
    (no I/O), as these run inline on the request path.
    """

    def create_response(self, content: str, status_code: int) -> GuardResponse:
        """Build a response carrying ``content`` and ``status_code``."""
        ...

    def create_redirect_response(self, url: str, status_code: int) -> GuardResponse:
        """Build a redirect response pointing at ``url`` with ``status_code``."""
        ...
