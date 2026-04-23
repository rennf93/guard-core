from unittest.mock import MagicMock

import pytest

pytest.importorskip("opentelemetry.sdk")

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from guard_core.core.events.composite_handler import CompositeAgentHandler
from guard_core.core.events.event_types import (
    EVENT_CLOUD_BLOCKED,
    EVENT_PENETRATION_ATTEMPT,
    EventFilter,
)
from guard_core.core.events.middleware_events import SecurityEventBus
from guard_core.core.events.otel_handler import OtelHandler
from guard_core.models import SecurityConfig


def _build_request() -> MagicMock:
    request = MagicMock()
    request.client_host = "1.2.3.4"
    request.headers = {}
    request.url_path = "/x"
    request.method = "GET"
    request.state = type("S", (), {})()
    return request


def _build_otel_handler_with_exporter(
    config: SecurityConfig, exporter: InMemorySpanExporter
) -> OtelHandler:
    handler = OtelHandler(config)
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    handler._tracer = provider.get_tracer("guard_core.otel")
    handler._meter = None
    handler._rt_histogram = None
    handler._request_counter = None
    handler._error_counter = None
    return handler


def _build_wired_event_bus(
    config: SecurityConfig, exporter: InMemorySpanExporter
) -> SecurityEventBus:
    otel = _build_otel_handler_with_exporter(config, exporter)
    composite = CompositeAgentHandler([otel])
    event_filter = EventFilter(
        muted_event_types=frozenset(config.muted_event_types),
        muted_metric_types=frozenset(config.muted_metric_types),
    )
    return SecurityEventBus(
        agent_handler=composite,
        config=config,
        event_filter=event_filter,
    )


async def test_end_to_end_span_emission_with_otel(monkeypatch) -> None:
    exporter = InMemorySpanExporter()
    config = SecurityConfig(enable_otel=True, agent_enable_events=True)

    fake_event_cls = MagicMock(side_effect=lambda **kw: type("E", (), kw)())
    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.SecurityEvent",
        fake_event_cls,
        raising=False,
    )

    async def fake_extract(*_a, **_kw) -> str:
        return "1.2.3.4"

    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.extract_client_ip",
        fake_extract,
    )
    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.get_pipeline_response_time",
        lambda _r: 0.0,
    )

    bus = _build_wired_event_bus(config, exporter)

    await bus.send_middleware_event(
        event_type=EVENT_PENETRATION_ATTEMPT,
        request=_build_request(),
        action_taken="blocked",
        reason="integration test",
    )

    spans = exporter.get_finished_spans()
    names = [s.name for s in spans]
    assert "guard.event.penetration_attempt" in names, names
    span = next(s for s in spans if s.name == "guard.event.penetration_attempt")
    assert span.attributes["guard.event_type"] == "penetration_attempt"
    assert span.attributes["guard.action_taken"] == "blocked"


async def test_end_to_end_mute_suppresses_span(monkeypatch) -> None:
    exporter = InMemorySpanExporter()
    config = SecurityConfig(
        enable_otel=True,
        agent_enable_events=True,
        muted_event_types={EVENT_CLOUD_BLOCKED},
    )

    fake_event_cls = MagicMock(side_effect=lambda **kw: type("E", (), kw)())
    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.SecurityEvent",
        fake_event_cls,
        raising=False,
    )

    async def fake_extract(*_a, **_kw) -> str:
        return "1.2.3.4"

    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.extract_client_ip",
        fake_extract,
    )
    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.get_pipeline_response_time",
        lambda _r: 0.0,
    )

    bus = _build_wired_event_bus(config, exporter)

    await bus.send_middleware_event(
        event_type=EVENT_CLOUD_BLOCKED,
        request=_build_request(),
        action_taken="blocked",
        reason="muted",
    )

    spans = exporter.get_finished_spans()
    assert not any(s.name == "guard.event.cloud_blocked" for s in spans)


async def test_end_to_end_traceparent_passes_through_event_bus(monkeypatch) -> None:
    captured: dict[str, object] = {}

    async def capture_send(event):
        captured["event"] = event

    composite = MagicMock()
    composite.send_event = capture_send

    cfg = SecurityConfig(enable_otel=True, agent_enable_events=True)
    bus = SecurityEventBus(agent_handler=composite, config=cfg)

    fake_event_cls = MagicMock(side_effect=lambda **kw: type("E", (), kw)())
    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.SecurityEvent",
        fake_event_cls,
        raising=False,
    )

    async def fake_extract(*_a, **_kw) -> str:
        return "1.2.3.4"

    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.extract_client_ip",
        fake_extract,
    )
    monkeypatch.setattr(
        "guard_core.core.events.middleware_events.get_pipeline_response_time",
        lambda _r: 0.0,
    )

    traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    request = _build_request()
    request.headers = {"traceparent": traceparent}

    await bus.send_middleware_event(
        event_type=EVENT_PENETRATION_ATTEMPT,
        request=request,
        action_taken="blocked",
        reason="with trace",
    )

    event = captured["event"]
    assert event.metadata["traceparent"] == traceparent
