import threading

from guard_core.sync.detection_engine.monitor import PerformanceMonitor

_N_THREADS = 16
_ITERATIONS = 2000
_MIN_SAMPLES_FOR_ANOMALY = 20


def test_record_metric_concurrent_threads_do_not_raise() -> None:
    monitor = PerformanceMonitor(
        min_samples_for_anomaly=_MIN_SAMPLES_FOR_ANOMALY, anomaly_threshold=1.0
    )
    errors: list[BaseException] = []
    barrier = threading.Barrier(_N_THREADS)

    def worker() -> None:
        barrier.wait()
        try:
            for i in range(_ITERATIONS):
                monitor.record_metric(
                    pattern="shared_pattern",
                    execution_time=0.001 + (i % 5) * 1e-4,
                    content_length=100,
                    matched=False,
                )
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(_N_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"unexpected concurrency errors: {errors}"
    assert (
        monitor.pattern_stats["shared_pattern"].total_executions
        == _N_THREADS * _ITERATIONS
    )


def test_get_summary_stats_concurrent_with_record_metric_does_not_raise() -> None:
    monitor = PerformanceMonitor(
        min_samples_for_anomaly=_MIN_SAMPLES_FOR_ANOMALY, anomaly_threshold=1.0
    )
    errors: list[BaseException] = []
    barrier = threading.Barrier(_N_THREADS)
    stop = threading.Event()

    def writer() -> None:
        barrier.wait()
        try:
            for i in range(_ITERATIONS):
                monitor.record_metric(
                    pattern="shared_pattern",
                    execution_time=0.001 + (i % 5) * 1e-4,
                    content_length=100,
                    matched=False,
                )
        except Exception as e:
            errors.append(e)

    def reader() -> None:
        try:
            while not stop.is_set():
                monitor.get_summary_stats()
        except Exception as e:
            errors.append(e)

    writers = [threading.Thread(target=writer) for _ in range(_N_THREADS)]
    reader_thread = threading.Thread(target=reader)
    reader_thread.start()
    for t in writers:
        t.start()
    for t in writers:
        t.join()
    stop.set()
    reader_thread.join()

    assert errors == [], f"unexpected concurrency errors: {errors}"
