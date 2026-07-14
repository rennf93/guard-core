import threading

import pytest

from guard_core.detection_engine import compiler


class _RaceWinnerLock:
    """A lock stand-in that simulates another thread initializing
    `_shared_executor` while this thread was waiting to acquire the lock."""

    def __init__(self, sentinel: object) -> None:
        self._sentinel = sentinel

    def __enter__(self) -> "_RaceWinnerLock":
        compiler._shared_executor = self._sentinel  # type: ignore[assignment]
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def test_shared_executor_skips_reinit_when_set_during_lock_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compiler._shared_executor = None
    sentinel = object()
    monkeypatch.setattr(compiler, "_executor_lock", _RaceWinnerLock(sentinel))

    result = compiler.shared_regex_executor()

    assert result is sentinel


def test_shared_executor_is_singleton_under_concurrent_first_call() -> None:
    compiler._shared_executor = None
    seen = []
    barrier = threading.Barrier(8)

    def grab() -> None:
        barrier.wait()
        seen.append(id(compiler.shared_regex_executor()))

    threads = [threading.Thread(target=grab) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(set(seen)) == 1
