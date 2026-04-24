from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("guard_core")

try:
    from opentelemetry import metrics, trace
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
        OTLPMetricExporter,
    )
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter,
    )
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.trace.propagation.tracecontext import (
        TraceContextTextMapPropagator,
    )

    _otel_available = True
except ImportError:
    metrics = None
    trace = None
    OTLPMetricExporter = None
    OTLPSpanExporter = None
    MeterProvider = None
    PeriodicExportingMetricReader = None
    Resource = None
    TracerProvider = None
    BatchSpanProcessor = None
    TraceContextTextMapPropagator = None
    _otel_available = False


class OtelHandler:
    def __init__(self, config: Any) -> None:
        self._config = config
        self._tracer: Any = None
        self._meter: Any = None
        self._rt_histogram: Any = None
        self._request_counter: Any = None
        self._error_counter: Any = None

    async def start(self) -> None:
        if not _otel_available:
            logger.warning("opentelemetry-sdk not installed, OTEL handler disabled")
            return
        attrs: dict[str, Any] = {"service.name": self._config.otel_service_name}
        extra = getattr(self._config, "otel_resource_attributes", {}) or {}
        attrs.update(extra)
        resource = Resource.create(attrs)
        endpoint = self._config.otel_exporter_endpoint
        tp = TracerProvider(resource=resource)
        tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(tp)
        self._tracer = trace.get_tracer("guard_core.otel")
        reader = PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=endpoint))
        mp = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(mp)
        self._meter = metrics.get_meter("guard_core.otel")
        self._rt_histogram = self._meter.create_histogram(
            "guard.request.duration", unit="s"
        )
        self._request_counter = self._meter.create_counter("guard.request.count")
        self._error_counter = self._meter.create_counter("guard.error.count")

    async def stop(self) -> None:
        if self._tracer and _otel_available:
            tracer_provider = trace.get_tracer_provider()
            if hasattr(tracer_provider, "shutdown"):
                tracer_provider.shutdown()
            self._tracer = None
        if self._meter and _otel_available:
            meter_provider = metrics.get_meter_provider()
            if hasattr(meter_provider, "shutdown"):
                meter_provider.shutdown()
            self._meter = None

    async def send_event(self, event: Any) -> None:
        if not _otel_available or not self._tracer:
            return
        event_type = getattr(event, "event_type", "unknown")
        metadata = getattr(event, "metadata", {}) or {}
        traceparent = (
            metadata.get("traceparent") if isinstance(metadata, dict) else None
        )
        tracestate = metadata.get("tracestate") if isinstance(metadata, dict) else None
        parent_ctx = None
        if traceparent:
            carrier: dict[str, str] = {"traceparent": traceparent}
            if tracestate:
                carrier["tracestate"] = tracestate
            try:
                propagator = TraceContextTextMapPropagator()
                parent_ctx = propagator.extract(carrier=carrier)
            except Exception:
                parent_ctx = None

        with self._tracer.start_as_current_span(
            f"guard.event.{event_type}", context=parent_ctx
        ) as span:
            span.set_attribute("guard.event_type", event_type)
            span.set_attribute("guard.ip_address", getattr(event, "ip_address", ""))
            span.set_attribute("guard.action_taken", getattr(event, "action_taken", ""))
            span.set_attribute("guard.reason", getattr(event, "reason", ""))
            span.set_attribute("guard.endpoint", getattr(event, "endpoint", ""))
            span.set_attribute("guard.method", getattr(event, "method", ""))
            status_code = getattr(event, "status_code", 0)
            if status_code:
                span.set_attribute("guard.status_code", status_code)
            if isinstance(metadata, dict):
                for key, value in metadata.items():
                    if (
                        key.startswith("guard.")
                        and key not in ("traceparent", "tracestate")
                        and value is not None
                    ):
                        span.set_attribute(key, value)

    async def send_metric(self, metric: Any) -> None:
        if not _otel_available or not self._meter:
            return
        metric_type = getattr(metric, "metric_type", "unknown")
        value = getattr(metric, "value", 0)
        endpoint = getattr(metric, "endpoint", "")
        tags = getattr(metric, "tags", {}) or {}
        attrs = {"endpoint": endpoint, **tags}
        if metric_type == "response_time" and self._rt_histogram:
            self._rt_histogram.record(value, attributes=attrs)
        elif metric_type == "request_count" and self._request_counter:
            self._request_counter.add(value, attributes=attrs)
        elif metric_type == "error_rate" and self._error_counter:
            self._error_counter.add(value, attributes=attrs)
        else:
            logger.warning(
                "Unknown OTEL metric type %s - no instrument recorded", metric_type
            )

    async def initialize_redis(self, redis_handler: Any) -> None:
        pass

    async def flush_buffer(self) -> None:
        pass

    async def get_dynamic_rules(self) -> Any | None:
        return None

    async def health_check(self) -> bool:
        return _otel_available
