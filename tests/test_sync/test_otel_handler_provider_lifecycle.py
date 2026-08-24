import subprocess
import sys
import textwrap

_PREAMBLE = textwrap.dedent(
    """
    import io
    import threading
    from unittest.mock import MagicMock, patch

    from opentelemetry import metrics, trace
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import ConsoleMetricExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider

    def fake_span_exporter(**_kwargs):
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )

        return InMemorySpanExporter()

    def fake_metric_exporter(**_kwargs):
        return ConsoleMetricExporter(out=io.StringIO())

    _patches = [
        patch(
            "guard_core.sync.core.events.otel_handler.OTLPSpanExporter",
            fake_span_exporter,
        ),
        patch(
            "guard_core.sync.core.events.otel_handler.OTLPMetricExporter",
            fake_metric_exporter,
        ),
    ]
    for _p in _patches:
        _p.start()

    from guard_core.sync.core.events.otel_handler import OtelHandler

    class Config:
        otel_service_name = "guard-core-test"
        otel_exporter_endpoint = "http://localhost:4318"
        otel_resource_attributes: dict = {}

    def otel_thread_names():
        return {t.name for t in threading.enumerate() if t.name.startswith("Otel")}
    """
)


def _run_snippet(body: str) -> subprocess.CompletedProcess[str]:
    script = _PREAMBLE + "\n\n" + textwrap.dedent(body)
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_start_never_shuts_down_a_pre_existing_ambient_provider_pair() -> None:
    result = _run_snippet(
        """
        def main():
            host_tracer_provider = TracerProvider(
                resource=Resource.create({"service.name": "host-app"})
            )
            host_tracer_provider.shutdown = MagicMock(
                wraps=host_tracer_provider.shutdown
            )
            trace.set_tracer_provider(host_tracer_provider)

            host_meter_provider = MeterProvider(
                resource=Resource.create({"service.name": "host-app"})
            )
            host_meter_provider.shutdown = MagicMock(
                wraps=host_meter_provider.shutdown
            )
            metrics.set_meter_provider(host_meter_provider)

            handler = OtelHandler(Config())
            handler.start()

            assert trace.get_tracer_provider() is host_tracer_provider
            assert metrics.get_meter_provider() is host_meter_provider
            assert handler._owned_tracer_provider is None
            assert handler._owned_meter_provider is None
            assert handler._tracer is not None
            assert handler._meter is not None

            handler.stop()

            host_tracer_provider.shutdown.assert_not_called()
            host_meter_provider.shutdown.assert_not_called()

        main()
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_second_instance_never_owns_or_destroys_the_first_instances_providers() -> None:
    result = _run_snippet(
        """
        def main():
            handler_a = OtelHandler(Config())
            handler_b = OtelHandler(Config())

            handler_a.start()
            owned_tracer_provider = handler_a._owned_tracer_provider
            owned_meter_provider = handler_a._owned_meter_provider
            assert owned_tracer_provider is not None
            assert owned_meter_provider is not None
            owned_tracer_provider.shutdown = MagicMock(
                wraps=owned_tracer_provider.shutdown
            )
            owned_meter_provider.shutdown = MagicMock(
                wraps=owned_meter_provider.shutdown
            )

            threads_after_a = otel_thread_names()

            handler_b.start()

            assert trace.get_tracer_provider() is owned_tracer_provider
            assert metrics.get_meter_provider() is owned_meter_provider
            assert handler_b._owned_tracer_provider is None
            assert handler_b._owned_meter_provider is None
            assert handler_b._tracer is not None
            assert handler_b._meter is not None
            assert otel_thread_names() == threads_after_a, (
                "B.start() must not leak new export threads"
            )

            handler_b.stop()

            owned_tracer_provider.shutdown.assert_not_called()
            owned_meter_provider.shutdown.assert_not_called()
            assert otel_thread_names() == threads_after_a, (
                "B.stop() must not touch A's live threads"
            )

            handler_a.stop()

            owned_tracer_provider.shutdown.assert_called_once()
            owned_meter_provider.shutdown.assert_called_once()
            assert otel_thread_names() == set()

        main()
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_stop_before_start_and_double_stop_are_safe() -> None:
    result = _run_snippet(
        """
        def main():
            handler = OtelHandler(Config())
            handler.stop()
            assert handler._tracer is None
            assert handler._meter is None

            handler.start()
            assert handler._owned_tracer_provider is not None
            assert handler._owned_meter_provider is not None

            handler.stop()
            assert handler._owned_tracer_provider is None
            assert handler._owned_meter_provider is None

            handler.stop()
            assert handler._owned_tracer_provider is None
            assert handler._owned_meter_provider is None
            assert otel_thread_names() == set()

        main()
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_shutdown_arriving_again_after_stop_already_ran_is_safe() -> None:
    result = _run_snippet(
        """
        def main():
            handler = OtelHandler(Config())
            handler.start()
            owned_tracer_provider = handler._owned_tracer_provider
            owned_meter_provider = handler._owned_meter_provider

            handler.stop()
            assert handler._owned_tracer_provider is None
            assert handler._owned_meter_provider is None

            owned_tracer_provider.shutdown()
            owned_meter_provider.shutdown()

            handler.stop()
            assert otel_thread_names() == set()

        main()
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_start_after_stop_is_safe_though_functionally_inert() -> None:
    result = _run_snippet(
        """
        def main():
            handler = OtelHandler(Config())
            handler.start()
            handler.stop()

            handler.start()
            assert handler._tracer is not None
            assert handler._meter is not None
            assert handler._owned_tracer_provider is None, (
                "opentelemetry's global provider is set-once per process; "
                "guard_core cannot reclaim ownership after its own shutdown"
            )
            assert handler._owned_meter_provider is None

            handler.stop()
            assert otel_thread_names() == set()

        main()
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_concurrent_start_across_many_instances_yields_exactly_one_owner() -> None:
    result = _run_snippet(
        """
        def main():
            n = 6
            handlers = [OtelHandler(Config()) for _ in range(n)]
            errors = []
            barrier = threading.Barrier(n)

            def run_start(h):
                barrier.wait()
                try:
                    h.start()
                except BaseException as e:
                    errors.append(e)

            threads = [threading.Thread(target=run_start, args=(h,)) for h in handlers]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert errors == [], errors
            owners = [h for h in handlers if h._owned_tracer_provider is not None]
            assert len(owners) == 1, len(owners)
            assert all(h._tracer is not None for h in handlers)
            assert all(h._meter is not None for h in handlers)

            stop_errors = []
            barrier2 = threading.Barrier(n)

            def run_stop(h):
                barrier2.wait()
                try:
                    h.stop()
                except BaseException as e:
                    stop_errors.append(e)

            stop_threads = [
                threading.Thread(target=run_stop, args=(h,)) for h in handlers
            ]
            for t in stop_threads:
                t.start()
            for t in stop_threads:
                t.join()

            assert stop_errors == [], stop_errors
            assert otel_thread_names() == set()

        main()
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr
