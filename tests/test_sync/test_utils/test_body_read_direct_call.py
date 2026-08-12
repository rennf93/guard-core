import threading
import time
from typing import cast

from guard_core.sync import utils
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


def test_safe_read_has_no_thread_pool_or_semaphore_machinery() -> None:
    assert not hasattr(utils, "_body_read_slots")
    assert not hasattr(utils, "_BODY_READ_EXECUTOR_MAX_WORKERS")
    assert not hasattr(utils, "_run_and_release_body_read_slot")


def test_safe_read_calls_the_reader_directly_without_spawning_a_thread() -> None:
    before = threading.active_count()

    result = utils._safe_read(lambda: b"payload", timeout=1.0)

    assert result == b"payload"
    assert threading.active_count() == before


def test_a_stalled_reader_blocks_the_caller_for_its_real_duration() -> None:
    def _stall() -> bytes:
        time.sleep(0.2)
        return b"finally-done"

    started = time.monotonic()
    result = utils._safe_read(_stall, timeout=0.01)
    elapsed = time.monotonic() - started

    assert result == b"finally-done"
    assert elapsed >= 0.2


def test_a_raising_reader_degrades_to_none_with_no_thread_involved() -> None:
    def _raise() -> bytes:
        raise RuntimeError("adapter stream closed")

    result = utils._safe_read(_raise, timeout=1.0)

    assert result is None


def test_forty_concurrent_ordinary_reads_skip_zero_detections() -> None:
    n = 40
    barrier = threading.Barrier(n)
    results: list[bytes | None] = [None] * n

    def worker(i: int) -> None:
        barrier.wait()

        def reader() -> bytes:
            time.sleep(0.02)
            return f"order-{i}".encode()

        results[i] = utils._safe_read(reader, timeout=2.0)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    skipped = sum(1 for r in results if r is None)
    assert skipped == 0
    assert results == [f"order-{i}".encode() for i in range(n)]


def test_read_and_cache_body_ignores_the_timeout_argument_entirely() -> None:
    class _State:
        pass

    class _Request:
        def __init__(self) -> None:
            self.state = _State()

    def reader() -> bytes:
        time.sleep(0.1)
        return b"slow-but-honest"

    started = time.monotonic()
    result = utils._read_and_cache_body(
        cast(SyncGuardRequest, _Request()), 1024, 0.001, reader, "body"
    )
    elapsed = time.monotonic() - started

    assert result == b"slow-but-honest"
    assert elapsed >= 0.1


def _guard_body_read_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name.startswith("guard-body-read")]


def test_no_guard_body_read_threads_are_ever_spawned() -> None:
    def reader() -> bytes:
        return b"x"

    for _ in range(5):
        utils._safe_read(reader, timeout=1.0)

    assert _guard_body_read_threads() == []
