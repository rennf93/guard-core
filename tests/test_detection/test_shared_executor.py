import threading

import pytest

from guard_core.detection_engine import compiler


class _RaceWinnerLock:
    """A lock stand-in that simulates another thread initializing the target
    executor attribute while this thread was waiting to acquire the lock."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, attr_name: str, sentinel: object
    ) -> None:
        self._monkeypatch = monkeypatch
        self._attr_name = attr_name
        self._sentinel = sentinel

    def __enter__(self) -> "_RaceWinnerLock":
        self._monkeypatch.setattr(compiler, self._attr_name, self._sentinel)
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def test_shared_executor_skips_reinit_when_set_during_lock_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(compiler, "_shared_executor", None)
    sentinel = object()
    monkeypatch.setattr(
        compiler,
        "_executor_lock",
        _RaceWinnerLock(monkeypatch, "_shared_executor", sentinel),
    )

    result = compiler.shared_regex_executor()

    assert result is sentinel


def test_shared_executor_is_singleton_under_concurrent_first_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(compiler, "_shared_executor", None)
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


def test_validation_executor_skips_reinit_when_set_during_lock_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(compiler, "_validation_executor", None)
    sentinel = object()
    monkeypatch.setattr(
        compiler,
        "_validation_executor_lock",
        _RaceWinnerLock(monkeypatch, "_validation_executor", sentinel),
    )

    result = compiler.validation_regex_executor()

    assert result is sentinel


def test_report_scan_timeout_swaps_pool_with_no_prior_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(compiler, "_shared_executor", None)
    monkeypatch.setattr(compiler, "_consecutive_timeouts", 0)

    for _ in range(compiler._SHARED_EXECUTOR_MAX_WORKERS):
        compiler.report_scan_timeout()

    assert compiler._shared_executor is not None
    assert compiler._consecutive_timeouts == 0
