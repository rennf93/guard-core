import threading

from guard_core.sync.detection_engine import compiler


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
