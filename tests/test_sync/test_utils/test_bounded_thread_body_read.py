import inspect
import logging
import threading
import time
from typing import cast

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync import utils
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


def _guard_body_read_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == "guard-body-read"]


class _StallingBoundedRequest:
    def __init__(self, release: threading.Event) -> None:
        self._release = release
        self.query_params: dict[str, str] = {}
        self.headers: dict[str, str] = {}
        self.state = type("S", (), {})()

    def read_body_prefix(self, max_bytes: int) -> bytes:
        self._release.wait()
        return b"late"


def test_security_config_sync_body_read_max_concurrent_bounds_real_reads() -> None:
    release = threading.Event()
    config = SecurityConfig(sync_body_read_max_concurrent=2)

    def _attempt() -> None:
        request = _StallingBoundedRequest(release)
        utils._read_capped_body(cast(SyncGuardRequest, request), config)

    callers = [threading.Thread(target=_attempt) for _ in range(10)]
    for c in callers:
        c.start()
    for c in callers:
        c.join(timeout=5)

    spawned = _guard_body_read_threads()
    assert len(spawned) == 2

    release.set()
    for t in spawned:
        t.join(timeout=2)


def test_no_thread_pool_executor_machinery_is_used() -> None:
    assert not hasattr(utils, "ThreadPoolExecutor")
    assert "ThreadPoolExecutor" not in inspect.getsource(utils._safe_read)


def test_a_successful_read_returns_the_value() -> None:
    result = utils._safe_read(lambda: b"payload", timeout=1.0, max_concurrent=21)

    assert result == b"payload"


def test_a_raising_reader_degrades_to_none() -> None:
    def _raise() -> bytes:
        raise RuntimeError("adapter stream closed")

    result = utils._safe_read(_raise, timeout=1.0, max_concurrent=22)

    assert result is None


def test_a_genuinely_stalled_read_degrades_to_none_within_the_timeout() -> None:
    def _stall() -> bytes:
        time.sleep(0.4)
        return b"too-late"

    started = time.monotonic()
    result = utils._safe_read(_stall, timeout=0.1, max_concurrent=23)
    elapsed = time.monotonic() - started

    assert result is None
    assert elapsed < 0.4

    for t in _guard_body_read_threads():
        t.join(timeout=2)


def test_body_read_threads_are_daemon_threads() -> None:
    max_concurrent = 24
    release = threading.Event()

    def _stall() -> bytes:
        release.wait()
        return b"late"

    caller = threading.Thread(
        target=utils._safe_read, args=(_stall, 5.0, max_concurrent)
    )
    caller.start()
    time.sleep(0.1)

    spawned = _guard_body_read_threads()
    assert spawned
    assert all(t.daemon for t in spawned)

    release.set()
    caller.join(timeout=2)
    for t in spawned:
        t.join(timeout=2)


def test_thread_count_stays_bounded_across_many_stall_cycles() -> None:
    max_concurrent = 3
    release = threading.Event()

    def _stall() -> bytes:
        release.wait()
        return b"late"

    def _attempt() -> None:
        utils._safe_read(_stall, timeout=0.05, max_concurrent=max_concurrent)

    callers = [threading.Thread(target=_attempt) for _ in range(25)]
    for c in callers:
        c.start()
    for c in callers:
        c.join(timeout=5)

    spawned = _guard_body_read_threads()
    assert len(spawned) == max_concurrent

    release.set()
    for t in spawned:
        t.join(timeout=2)


@pytest.mark.parametrize("max_concurrent", [2, 6])
def test_concurrency_limit_is_configurable_per_call(max_concurrent: int) -> None:
    release = threading.Event()

    def _stall() -> bytes:
        release.wait()
        return b"late"

    def _attempt() -> None:
        utils._safe_read(_stall, timeout=0.05, max_concurrent=max_concurrent)

    callers = [threading.Thread(target=_attempt) for _ in range(max_concurrent + 10)]
    for c in callers:
        c.start()
    for c in callers:
        c.join(timeout=5)

    spawned = _guard_body_read_threads()
    assert len(spawned) == max_concurrent

    release.set()
    for t in spawned:
        t.join(timeout=2)


def test_forty_concurrent_ordinary_reads_skip_zero_even_with_a_small_limit() -> None:
    max_concurrent = 5
    n = 40
    results: list[bytes | None] = [None] * n
    barrier = threading.Barrier(n)

    def _worker(i: int) -> None:
        barrier.wait()

        def reader() -> bytes:
            time.sleep(0.02)
            return f"order-{i}".encode()

        results[i] = utils._safe_read(
            reader, timeout=2.0, max_concurrent=max_concurrent
        )

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    skipped = sum(1 for r in results if r is None)
    assert skipped == 0
    assert results == [f"order-{i}".encode() for i in range(n)]


def test_exhaustion_emits_a_diagnostic_log(caplog: pytest.LogCaptureFixture) -> None:
    max_concurrent = 1
    release = threading.Event()

    def _stall() -> bytes:
        release.wait()
        return b"late"

    holder = threading.Thread(
        target=utils._safe_read, args=(_stall, 5.0, max_concurrent)
    )
    holder.start()
    time.sleep(0.1)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = utils._safe_read(_stall, timeout=0.1, max_concurrent=max_concurrent)

    assert result is None
    assert "concurrency limit" in caplog.text.lower()

    release.set()
    holder.join(timeout=2)
    for t in _guard_body_read_threads():
        t.join(timeout=2)


def test_read_and_cache_body_now_honors_the_timeout_instead_of_blocking() -> None:
    class _State:
        pass

    class _Request:
        def __init__(self) -> None:
            self.state = _State()

    def _stall() -> bytes:
        time.sleep(0.4)
        return b"too-slow"

    started = time.monotonic()
    result = utils._read_and_cache_body(
        cast(SyncGuardRequest, _Request()), 1024, 0.05, _stall, "body", 25
    )
    elapsed = time.monotonic() - started

    assert result is None
    assert elapsed < 0.4

    for t in _guard_body_read_threads():
        t.join(timeout=2)
