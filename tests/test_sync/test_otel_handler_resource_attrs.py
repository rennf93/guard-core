import importlib
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig


def _fresh_otel_handler_module():
    module_name = "guard_core.sync.core.events.otel_handler"
    if module_name in sys.modules:
        return importlib.reload(sys.modules[module_name])
    return importlib.import_module(module_name)


@pytest.fixture(autouse=True)
def _reload_otel_handler_between_tests():
    _fresh_otel_handler_module()
    yield
    _fresh_otel_handler_module()


def test_otel_resource_attributes_default_empty() -> None:
    assert SecurityConfig().otel_resource_attributes == {}


def test_otel_handler_applies_resource_attributes() -> None:
    module = _fresh_otel_handler_module()
    fake_resource = MagicMock()
    fake_resource_cls = MagicMock()
    fake_resource_cls.create = MagicMock(return_value=fake_resource)

    with (
        patch.object(module, "_otel_available", True),
        patch.object(module, "Resource", fake_resource_cls),
        patch.object(module, "TracerProvider"),
        patch.object(module, "BatchSpanProcessor"),
        patch.object(module, "OTLPSpanExporter"),
        patch.object(module, "OTLPMetricExporter"),
        patch.object(module, "PeriodicExportingMetricReader"),
        patch.object(module, "MeterProvider"),
        patch.object(module, "trace"),
        patch.object(module, "metrics"),
    ):
        config = SimpleNamespace(
            otel_service_name="guard-core",
            otel_exporter_endpoint="http://localhost:4318",
            otel_resource_attributes={
                "deployment.environment": "prod",
                "service.version": "1.0.3",
            },
        )
        handler = module.OtelHandler(config)
        handler.start()

    fake_resource_cls.create.assert_called_once()
    attrs = fake_resource_cls.create.call_args.args[0]
    assert attrs["service.name"] == "guard-core"
    assert attrs["deployment.environment"] == "prod"
    assert attrs["service.version"] == "1.0.3"


def test_send_event_extracts_traceparent_from_metadata() -> None:
    module = _fresh_otel_handler_module()
    propagator = MagicMock()
    propagator.extract = MagicMock(return_value="resumed_context")
    prop_cls = MagicMock(return_value=propagator)

    tracer = MagicMock()
    span_cm = MagicMock()
    span = MagicMock()
    span_cm.__enter__ = MagicMock(return_value=span)
    span_cm.__exit__ = MagicMock(return_value=False)
    tracer.start_as_current_span = MagicMock(return_value=span_cm)

    with (
        patch.object(module, "_otel_available", True),
        patch.object(module, "TraceContextTextMapPropagator", prop_cls),
    ):
        handler = module.OtelHandler(
            config=SimpleNamespace(
                otel_service_name="svc",
                otel_exporter_endpoint=None,
                otel_resource_attributes={},
            )
        )
        handler._tracer = tracer

        event = SimpleNamespace(
            event_type="penetration_attempt",
            ip_address="1.2.3.4",
            action_taken="blocked",
            reason="test",
            endpoint="/x",
            method="GET",
            status_code=0,
            metadata={
                "traceparent": (
                    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
                )
            },
        )
        handler.send_event(event)

    propagator.extract.assert_called_once()
    call = propagator.extract.call_args
    carrier = call.kwargs.get("carrier") or (call.args[0] if call.args else None)
    assert carrier == {
        "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    }
    tracer.start_as_current_span.assert_called_once()
    sas_kwargs = tracer.start_as_current_span.call_args.kwargs
    assert sas_kwargs.get("context") == "resumed_context"


def test_send_event_forwards_tracestate_when_present() -> None:
    module = _fresh_otel_handler_module()
    propagator = MagicMock()
    propagator.extract = MagicMock(return_value="ctx")
    prop_cls = MagicMock(return_value=propagator)

    tracer = MagicMock()
    span_cm = MagicMock()
    span_cm.__enter__ = MagicMock(return_value=MagicMock())
    span_cm.__exit__ = MagicMock(return_value=False)
    tracer.start_as_current_span = MagicMock(return_value=span_cm)

    with (
        patch.object(module, "_otel_available", True),
        patch.object(module, "TraceContextTextMapPropagator", prop_cls),
    ):
        handler = module.OtelHandler(
            config=SimpleNamespace(
                otel_service_name="svc",
                otel_exporter_endpoint=None,
                otel_resource_attributes={},
            )
        )
        handler._tracer = tracer
        tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        event = SimpleNamespace(
            event_type="penetration_attempt",
            ip_address="1.2.3.4",
            action_taken="blocked",
            reason="",
            endpoint="",
            method="",
            status_code=0,
            metadata={"traceparent": tp, "tracestate": "vendor=abc"},
        )
        handler.send_event(event)

    carrier = propagator.extract.call_args.kwargs["carrier"]
    assert carrier == {"traceparent": tp, "tracestate": "vendor=abc"}


def test_send_event_no_traceparent_starts_root_span() -> None:
    module = _fresh_otel_handler_module()
    tracer = MagicMock()
    span_cm = MagicMock()
    span = MagicMock()
    span_cm.__enter__ = MagicMock(return_value=span)
    span_cm.__exit__ = MagicMock(return_value=False)
    tracer.start_as_current_span = MagicMock(return_value=span_cm)

    with patch.object(module, "_otel_available", True):
        handler = module.OtelHandler(
            config=SimpleNamespace(
                otel_service_name="svc",
                otel_exporter_endpoint=None,
                otel_resource_attributes={},
            )
        )
        handler._tracer = tracer

        event = SimpleNamespace(
            event_type="penetration_attempt",
            ip_address="1.2.3.4",
            action_taken="blocked",
            reason="",
            endpoint="",
            method="",
            status_code=0,
            metadata={},
        )
        handler.send_event(event)

    tracer.start_as_current_span.assert_called_once()
    sas_kwargs = tracer.start_as_current_span.call_args.kwargs
    assert sas_kwargs.get("context") is None


def test_send_metric_warns_on_unknown_type(caplog: pytest.LogCaptureFixture) -> None:
    import logging

    module = _fresh_otel_handler_module()
    with patch.object(module, "_otel_available", True):
        handler = module.OtelHandler(
            config=SimpleNamespace(
                otel_service_name="svc",
                otel_exporter_endpoint=None,
                otel_resource_attributes={},
            )
        )
        handler._meter = MagicMock()
        handler._rt_histogram = MagicMock()
        handler._request_counter = MagicMock()
        handler._error_counter = MagicMock()

        metric = SimpleNamespace(
            metric_type="new_metric_type",
            value=1.0,
            endpoint="/x",
            tags={},
        )
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            handler.send_metric(metric)

    messages = [r.getMessage() for r in caplog.records]
    assert any("unknown otel metric type" in m.lower() for m in messages), messages
    assert any("new_metric_type" in m for m in messages), messages
