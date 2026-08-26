import threading

from guard_core.sync.detection_engine.monitor import PerformanceMonitor


def test_record_metric_concurrent_threads_do_not_raise() -> None:
    monitor = PerformanceMonitor(min_samples_for_anomaly=50, anomaly_threshold=1.0)
    errors: list[BaseException] = []
    n_threads = 16
    iterations = 20000
    barrier = threading.Barrier(n_threads)

    def worker() -> None:
        barrier.wait()
        try:
            for i in range(iterations):
                monitor.record_metric(
                    pattern="shared_pattern",
                    execution_time=0.001 + (i % 5) * 1e-4,
                    content_length=100,
                    matched=False,
                )
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"unexpected concurrency errors: {errors}"
    assert (
        monitor.pattern_stats["shared_pattern"].total_executions
        == n_threads * iterations
    )
