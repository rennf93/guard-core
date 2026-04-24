from unittest.mock import MagicMock, patch

import pytest

from guard_core.core.events.otel_handler import OtelHandler


@pytest.fixture
def config() -> MagicMock:
    return MagicMock(
        otel_service_name="guard-core-test",
        otel_exporter_endpoint="http://localhost:4318",
    )


async def test_health_check_true_when_available(config: MagicMock) -> None:
    with patch("guard_core.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        assert await handler.health_check() is True


async def test_health_check_false_when_unavailable() -> None:
    with patch("guard_core.core.events.otel_handler._otel_available", False):
        handler = OtelHandler(MagicMock())
        assert await handler.health_check() is False


async def test_noop_when_otel_unavailable(config: MagicMock) -> None:
    with patch("guard_core.core.events.otel_handler._otel_available", False):
        handler = OtelHandler(config)
        await handler.send_event(MagicMock())
        await handler.send_metric(MagicMock())
        await handler.start()
        await handler.stop()
        await handler.flush_buffer()
        await handler.initialize_redis(MagicMock())


async def test_get_dynamic_rules_returns_none(config: MagicMock) -> None:
    handler = OtelHandler(config)
    assert await handler.get_dynamic_rules() is None


async def test_send_event_creates_span(config: MagicMock) -> None:
    with patch("guard_core.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        mock_tracer = MagicMock()
        mock_span = MagicMock()
        cm = MagicMock()
        cm.__enter__ = MagicMock(return_value=mock_span)
        cm.__exit__ = MagicMock(return_value=False)
        mock_tracer.start_as_current_span.return_value = cm
        handler._tracer = mock_tracer

        event = MagicMock()
        event.event_type = "penetration_attempt"
        event.ip_address = "1.2.3.4"
        event.action_taken = "blocked"
        event.reason = "test"
        event.endpoint = "/test"
        event.method = "GET"
        event.status_code = 403

        await handler.send_event(event)
        mock_tracer.start_as_current_span.assert_called_once()
        args, kwargs = mock_tracer.start_as_current_span.call_args
        assert args[0] == "guard.event.penetration_attempt"
        assert kwargs.get("context") is None
        assert mock_span.set_attribute.call_count >= 4


async def test_send_metric_records_histogram(config: MagicMock) -> None:
    with patch("guard_core.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        mock_histogram = MagicMock()
        mock_counter = MagicMock()
        mock_error_counter = MagicMock()
        handler._rt_histogram = mock_histogram
        handler._request_counter = mock_counter
        handler._error_counter = mock_error_counter
        handler._meter = MagicMock()

        metric = MagicMock()
        metric.metric_type = "response_time"
        metric.value = 0.5
        metric.endpoint = "/test"
        metric.tags = {"method": "GET"}

        await handler.send_metric(metric)
        mock_histogram.record.assert_called_once()
        mock_counter.add.assert_not_called()
        mock_error_counter.add.assert_not_called()


async def test_send_metric_records_counter(config: MagicMock) -> None:
    with patch("guard_core.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        mock_histogram = MagicMock()
        mock_counter = MagicMock()
        mock_error_counter = MagicMock()
        handler._rt_histogram = mock_histogram
        handler._request_counter = mock_counter
        handler._error_counter = mock_error_counter
        handler._meter = MagicMock()

        metric = MagicMock()
        metric.metric_type = "request_count"
        metric.value = 1.0
        metric.endpoint = "/test"
        metric.tags = {"method": "GET"}

        await handler.send_metric(metric)
        mock_counter.add.assert_called_once()
        mock_histogram.record.assert_not_called()


async def test_send_metric_records_error_counter(config: MagicMock) -> None:
    with patch("guard_core.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        mock_histogram = MagicMock()
        mock_counter = MagicMock()
        mock_error_counter = MagicMock()
        handler._rt_histogram = mock_histogram
        handler._request_counter = mock_counter
        handler._error_counter = mock_error_counter
        handler._meter = MagicMock()

        metric = MagicMock()
        metric.metric_type = "error_rate"
        metric.value = 1.0
        metric.endpoint = "/test"
        metric.tags = {"method": "GET"}

        await handler.send_metric(metric)
        mock_error_counter.add.assert_called_once()
        mock_histogram.record.assert_not_called()


async def test_stop_shuts_down_providers(config: MagicMock) -> None:
    with patch("guard_core.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        mock_tracer = MagicMock()
        mock_meter = MagicMock()
        handler._tracer = mock_tracer
        handler._meter = mock_meter
        mock_tracer_provider = MagicMock()
        mock_meter_provider = MagicMock()
        with (
            patch("guard_core.core.events.otel_handler.trace") as mock_trace,
            patch("guard_core.core.events.otel_handler.metrics") as mock_metrics,
        ):
            mock_trace.get_tracer_provider.return_value = mock_tracer_provider
            mock_metrics.get_meter_provider.return_value = mock_meter_provider
            await handler.stop()
        mock_tracer_provider.shutdown.assert_called_once()
        mock_meter_provider.shutdown.assert_called_once()


async def test_stop_no_tracer_or_meter(config: MagicMock) -> None:
    with patch("guard_core.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        handler._tracer = None
        handler._meter = None
        await handler.stop()


async def test_stop_is_idempotent(config: MagicMock) -> None:
    with patch("guard_core.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        handler._tracer = MagicMock()
        handler._meter = MagicMock()
        with (
            patch("guard_core.core.events.otel_handler.trace") as mock_trace,
            patch("guard_core.core.events.otel_handler.metrics") as mock_metrics,
        ):
            mock_trace.get_tracer_provider.return_value = MagicMock()
            mock_metrics.get_meter_provider.return_value = MagicMock()
            await handler.stop()
            await handler.stop()

        assert handler._tracer is None
        assert handler._meter is None


async def test_stop_providers_without_shutdown_attr(config: MagicMock) -> None:
    with patch("guard_core.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        handler._tracer = MagicMock()
        handler._meter = MagicMock()

        class _NoShutdown:
            pass

        with (
            patch("guard_core.core.events.otel_handler.trace") as mock_trace,
            patch("guard_core.core.events.otel_handler.metrics") as mock_metrics,
        ):
            mock_trace.get_tracer_provider.return_value = _NoShutdown()
            mock_metrics.get_meter_provider.return_value = _NoShutdown()
            await handler.stop()


async def test_start_configures_otel(config: MagicMock) -> None:
    with patch("guard_core.core.events.otel_handler._otel_available", True):
        handler = OtelHandler(config)
        mock_tracer = MagicMock()
        mock_meter = MagicMock()
        mock_histogram = MagicMock()
        mock_counter = MagicMock()
        mock_error_counter = MagicMock()
        mock_meter.create_histogram.return_value = mock_histogram
        mock_meter.create_counter.side_effect = [mock_counter, mock_error_counter]
        with (
            patch("guard_core.core.events.otel_handler.trace") as mock_trace,
            patch("guard_core.core.events.otel_handler.metrics") as mock_metrics,
            patch("guard_core.core.events.otel_handler.Resource") as MockResource,
            patch("guard_core.core.events.otel_handler.TracerProvider") as MockTP,
            patch("guard_core.core.events.otel_handler.BatchSpanProcessor"),
            patch("guard_core.core.events.otel_handler.OTLPSpanExporter"),
            patch("guard_core.core.events.otel_handler.PeriodicExportingMetricReader"),
            patch("guard_core.core.events.otel_handler.OTLPMetricExporter"),
            patch("guard_core.core.events.otel_handler.MeterProvider") as MockMP,
        ):
            mock_tp = MagicMock()
            MockTP.return_value = mock_tp
            mock_mp = MagicMock()
            MockMP.return_value = mock_mp
            mock_trace.get_tracer.return_value = mock_tracer
            mock_metrics.get_meter.return_value = mock_meter
            await handler.start()
            MockResource.create.assert_called_once()
            MockTP.assert_called_once()
            mock_tp.add_span_processor.assert_called_once()
            mock_trace.set_tracer_provider.assert_called_once_with(mock_tp)
            mock_trace.get_tracer.assert_called_once_with("guard_core.otel")
            MockMP.assert_called_once()
            mock_metrics.set_meter_provider.assert_called_once_with(mock_mp)
            mock_metrics.get_meter.assert_called_once_with("guard_core.otel")
            assert handler._tracer is mock_tracer
            assert handler._meter is mock_meter
            assert handler._rt_histogram is mock_histogram
            assert handler._request_counter is mock_counter
            assert handler._error_counter is mock_error_counter


def test_import_error_branch() -> None:
    import importlib
    import sys

    module_name = "guard_core.core.events.otel_handler"
    original = sys.modules.get(module_name)
    sys.modules.pop(module_name, None)
    for key in list(sys.modules.keys()):
        if key.startswith("opentelemetry"):
            sys.modules.pop(key, None)

    real_import = __import__

    def block_otel(name, *args, **kwargs):
        if name == "opentelemetry" or name.startswith("opentelemetry."):
            raise ImportError("opentelemetry not installed")
        return real_import(name, *args, **kwargs)

    try:
        with patch("builtins.__import__", side_effect=block_otel):
            mod = importlib.import_module(module_name)
            assert mod._otel_available is False
    finally:
        if module_name in sys.modules:
            del sys.modules[module_name]
        sys.modules[module_name] = (
            original if original else importlib.import_module(module_name)
        )
