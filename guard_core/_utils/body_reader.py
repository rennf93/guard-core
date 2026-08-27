import asyncio
import logging
import re
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from guard_core.protocols.request_protocol import GuardRequest

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig

logger = logging.getLogger("guard_core")

_CONTENT_LENGTH_RE = re.compile(r"[0-9]+")


def _parse_content_length(value: str) -> int | None:
    stripped = value.strip()
    if not _CONTENT_LENGTH_RE.fullmatch(stripped):
        return None
    parsed = int(stripped)
    return parsed if parsed > 0 else None


@runtime_checkable
class _BoundedBodyReader(Protocol):
    async def read_body_prefix(self, max_bytes: int) -> bytes: ...


_DEFAULT_BODY_READ_TIMEOUT = 3.0
_DEFAULT_BODY_READ_MAX_CONCURRENT = 64
_MAX_STRADDLE_OVERLAP_BYTES = 256


async def _safe_read(
    reader: Callable[[], Awaitable[bytes]],
    timeout: float,
    max_concurrent: int = _DEFAULT_BODY_READ_MAX_CONCURRENT,
) -> bytes | None:
    try:
        return await asyncio.wait_for(reader(), timeout=timeout)
    except Exception:
        return None


async def _straddle_overlap_bytes() -> int:
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    try:
        patterns = await sus_patterns_handler.get_all_compiled_patterns()
    except Exception:
        return 0

    if not patterns:
        return 0

    longest = max(len(pattern.pattern) for pattern, _contexts, _category in patterns)
    return min(longest, _MAX_STRADDLE_OVERLAP_BYTES)


_CAPPED_BODY_PREFIX_STATE_ATTR = "_guard_capped_body_prefix_cache"


async def _read_and_cache_body(
    request: GuardRequest,
    max_bytes: int,
    timeout: float,
    reader: Callable[[], Awaitable[bytes]],
    accessor: str,
    max_concurrent: int,
) -> bytes | None:
    cached = getattr(request.state, _CAPPED_BODY_PREFIX_STATE_ATTR, None)
    if cached is not None and cached[0] is request and cached[1] >= max_bytes:
        cached_bytes: bytes = cached[2]
        return cached_bytes[:max_bytes]

    prefix: object = await _safe_read(reader, timeout, max_concurrent)
    if prefix is None:
        return None

    if not isinstance(prefix, bytes):
        logger.warning(
            "%s.%s returned %s, not bytes; treating the "
            "body as unavailable for detection",
            type(request).__name__,
            accessor,
            type(prefix).__name__,
        )
        return None

    capped = prefix[:max_bytes]
    setattr(request.state, _CAPPED_BODY_PREFIX_STATE_ATTR, (request, max_bytes, capped))
    return capped


async def _read_capped_body_prefix(
    request: GuardRequest, max_bytes: int, timeout: float, max_concurrent: int
) -> bytes | None:
    if not isinstance(request, _BoundedBodyReader):
        return None

    fetch_bytes = max_bytes + await _straddle_overlap_bytes()
    return await _read_and_cache_body(
        request,
        fetch_bytes,
        timeout,
        lambda: request.read_body_prefix(fetch_bytes),
        "read_body_prefix",
        max_concurrent,
    )


def _warn_body_inspect_bytes_cap_reached(max_bytes: int, client_ip: str) -> None:
    logger.warning(
        "detection_max_body_inspect_bytes (%d) reached for client %s; only the "
        "first %d bytes of the request body are scanned",
        max_bytes,
        client_ip,
        max_bytes,
    )


async def _read_capped_body(
    request: GuardRequest, config: "SecurityConfig | None", client_ip: str = ""
) -> bytes | None:
    if config is None:
        return await _safe_read(
            request.body, _DEFAULT_BODY_READ_TIMEOUT, _DEFAULT_BODY_READ_MAX_CONCURRENT
        )

    max_bytes = config.detection_max_body_inspect_bytes
    timeout = config.body_read_timeout
    max_concurrent = config.sync_body_read_max_concurrent
    content_length = request.headers.get("content-length")

    if content_length is not None:
        parsed = _parse_content_length(content_length)
        if parsed is not None:
            if parsed > max_bytes:
                _warn_body_inspect_bytes_cap_reached(max_bytes, client_ip)
            return await _read_and_cache_body(
                request, max_bytes, timeout, request.body, "body", max_concurrent
            )

    return await _read_capped_body_prefix(request, max_bytes, timeout, max_concurrent)
