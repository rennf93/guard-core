import threading
from unittest.mock import MagicMock

from guard_core.core.checks.helpers import _increment_suspicious_counts


def test_concurrent_threads_do_not_raise_or_lose_counts() -> None:
    mw = MagicMock()
    mw.suspicious_request_counts = {}
    errors: list[Exception] = []
    n_threads = 16
    barrier = threading.Barrier(n_threads)

    def worker(n: int) -> None:
        barrier.wait()
        try:
            for i in range(20):
                _increment_suspicious_counts(mw, f"task{n}-ip{i}", "ip_blocked")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len(mw.suspicious_request_counts) == n_threads * 20
    assert all(
        counts == {"ip_blocked": 1} for counts in mw.suspicious_request_counts.values()
    )


def test_concurrent_threads_incrementing_the_same_ip_sum_correctly() -> None:
    mw = MagicMock()
    mw.suspicious_request_counts = {}
    n_threads = 8
    barrier = threading.Barrier(n_threads)

    def worker() -> None:
        barrier.wait()
        for _ in range(50):
            _increment_suspicious_counts(mw, "shared-ip", "ip_blocked")

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert mw.suspicious_request_counts["shared-ip"] == {"ip_blocked": n_threads * 50}


def test_capacity_eviction_under_concurrent_threads_stays_within_cap() -> None:
    import guard_core.core.checks.helpers as helpers_mod

    original_cap = helpers_mod._MAX_TRACKED_SUSPICIOUS_IPS
    helpers_mod._MAX_TRACKED_SUSPICIOUS_IPS = 50
    try:
        mw = MagicMock()
        mw.suspicious_request_counts = {f"seed-{i}": {"x": 1} for i in range(50)}
        errors: list[Exception] = []
        n_threads = 16
        barrier = threading.Barrier(n_threads)

        def worker(n: int) -> None:
            barrier.wait()
            try:
                for i in range(200):
                    _increment_suspicious_counts(mw, f"thread{n}-ip{i}", "ip_blocked")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(mw.suspicious_request_counts) <= 50
    finally:
        helpers_mod._MAX_TRACKED_SUSPICIOUS_IPS = original_cap
