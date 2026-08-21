import logging
import re
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from guard_core.sync.protocols.request_protocol import SyncGuardRequest

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
    def read_body_prefix(self, max_bytes: int) -> bytes: ...


_DEFAULT_BODY_READ_TIMEOUT = 3.0
_DEFAULT_BODY_READ_MAX_CONCURRENT = 64
_MAX_STRADDLE_OVERLAP_BYTES = 256


_sync_body_read_semaphores: dict[int, threading.Semaphore] = {}
_sync_body_read_semaphores_lock = threading.Lock()


def _sync_body_read_semaphore(max_concurrent: int) -> threading.Semaphore:
    with _sync_body_read_semaphores_lock:
        semaphore = _sync_body_read_semaphores.get(max_concurrent)
        if semaphore is None:
            semaphore = threading.Semaphore(max_concurrent)
            _sync_body_read_semaphores[max_concurrent] = semaphore
        return semaphore


def _safe_read(
    reader: Callable[[], bytes],
    timeout: float,
    max_concurrent: int = _DEFAULT_BODY_READ_MAX_CONCURRENT,
) -> bytes | None:
    deadline = time.monotonic() + timeout
    semaphore = _sync_body_read_semaphore(max_concurrent)

    if not semaphore.acquire(timeout=max(deadline - time.monotonic(), 0.0)):
        logger.warning(
            "Sync body read concurrency limit reached (max_concurrent=%d); "
            "treating the body as unavailable for detection",
            max_concurrent,
        )
        return None

    result: bytes | None = None
    failed = False

    def _run() -> None:
        nonlocal result, failed
        try:
            result = reader()
        except Exception:
            failed = True
        finally:
            semaphore.release()

    thread = threading.Thread(target=_run, name="guard-body-read", daemon=True)
    thread.start()
    thread.join(timeout=max(deadline - time.monotonic(), 0.0))

    if thread.is_alive() or failed:
        return None
    return result


def _straddle_overlap_bytes() -> int:
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    try:
        patterns = sus_patterns_handler.get_all_compiled_patterns()
    except Exception:
        return 0

    if not patterns:
        return 0

    longest = max(len(pattern.pattern) for pattern, _contexts, _category in patterns)
    return min(longest, _MAX_STRADDLE_OVERLAP_BYTES)


_CAPPED_BODY_PREFIX_STATE_ATTR = "_guard_capped_body_prefix_cache"


def _read_and_cache_body(
    request: SyncGuardRequest,
    max_bytes: int,
    timeout: float,
    reader: Callable[[], bytes],
    accessor: str,
    max_concurrent: int,
) -> bytes | None:
    cached = getattr(request.state, _CAPPED_BODY_PREFIX_STATE_ATTR, None)
    if cached is not None and cached[0] is request and cached[1] >= max_bytes:
        cached_bytes: bytes = cached[2]
        return cached_bytes[:max_bytes]

    prefix: object = _safe_read(reader, timeout, max_concurrent)
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


def _read_capped_body_prefix(
    request: SyncGuardRequest, max_bytes: int, timeout: float, max_concurrent: int
) -> bytes | None:
    if not isinstance(request, _BoundedBodyReader):
        return None

    fetch_bytes = max_bytes + _straddle_overlap_bytes()
    return _read_and_cache_body(
        request,
        fetch_bytes,
        timeout,
        lambda: request.read_body_prefix(fetch_bytes),
        "read_body_prefix",
        max_concurrent,
    )


def _read_capped_body(
    request: SyncGuardRequest, config: "SecurityConfig | None"
) -> bytes | None:
    if config is None:
        return _safe_read(
            request.body, _DEFAULT_BODY_READ_TIMEOUT, _DEFAULT_BODY_READ_MAX_CONCURRENT
        )

    max_bytes = config.detection_max_body_inspect_bytes
    timeout = config.body_read_timeout
    max_concurrent = config.sync_body_read_max_concurrent
    content_length = request.headers.get("content-length")

    if content_length is not None:
        parsed = _parse_content_length(content_length)
        if parsed is not None and parsed > max_bytes:
            return None
        if parsed is not None:
            return _read_and_cache_body(
                request, max_bytes, timeout, request.body, "body", max_concurrent
            )

    return _read_capped_body_prefix(request, max_bytes, timeout, max_concurrent)
