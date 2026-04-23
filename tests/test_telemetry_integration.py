from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("opentelemetry.sdk")

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from guard_core.core.events.event_types import (
    EVENT_CLOUD_BLOCKED,
    EVENT_PENETRATION_ATTEMPT,
)
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.models import SecurityConfig


def _build_request() -> MagicMock:
    request = MagicMock()
    request.client_host = "1.2.3.4"
    request.headers = {}
    request.url_path = "/x"
    request.method = "GET"
    request.state = type("S", (), {})()
    return request


def _patch_otel_start(monkeypatch, exporter: InMemorySpanExporter) -> TracerProvider:
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    from guard_core.core.events import otel_handler as otel_mod

    async def patched_start(self) -> None:
        self._tracer = provider.get_tracer("guard_core.otel")
        self._meter = None
        self._rt_histogram = None
        self._request_counter = None
        self._error_counter = None

    monkeypatch.setattr(otel_mod.OtelHandler, "start", patched_start)
    return provider


async def test_end_to_end_span_emission_with_otel(monkeypatch) -> None:
    exporter = InMemorySpanExporter()
    _patch_otel_start(monkeypatch, exporter)

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

    config = SecurityConfig(enable_otel=True, agent_enable_events=True)
    initializer = HandlerInitializer(config=config, agent_handler=None)
    await initializer.initialize_agent_integrations()
    bus = initializer.build_event_bus()

    await bus.send_middleware_event(
        event_type=EVENT_PENETRATION_ATTEMPT,
        request=_build_request(),
        action_taken="blocked",
        reason="integration test",
    )

    await initializer.shutdown_agent_integrations()

    spans = exporter.get_finished_spans()
    names = [s.name for s in spans]
    assert "guard.event.penetration_attempt" in names, names
    span = next(s for s in spans if s.name == "guard.event.penetration_attempt")
    assert span.attributes["guard.event_type"] == "penetration_attempt"
    assert span.attributes["guard.action_taken"] == "blocked"


async def test_end_to_end_mute_suppresses_span(monkeypatch) -> None:
    exporter = InMemorySpanExporter()
    _patch_otel_start(monkeypatch, exporter)

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

    config = SecurityConfig(
        enable_otel=True,
        agent_enable_events=True,
        muted_event_types={EVENT_CLOUD_BLOCKED},
    )
    initializer = HandlerInitializer(config=config, agent_handler=None)
    await initializer.initialize_agent_integrations()
    bus = initializer.build_event_bus()

    await bus.send_middleware_event(
        event_type=EVENT_CLOUD_BLOCKED,
        request=_build_request(),
        action_taken="blocked",
        reason="muted",
    )

    await initializer.shutdown_agent_integrations()

    spans = exporter.get_finished_spans()
    assert not any(s.name == "guard.event.cloud_blocked" for s in spans)


async def test_end_to_end_traceparent_continuation(monkeypatch) -> None:
    exporter = InMemorySpanExporter()
    _patch_otel_start(monkeypatch, exporter)

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

    config = SecurityConfig(enable_otel=True, agent_enable_events=True)
    initializer = HandlerInitializer(config=config, agent_handler=None)
    await initializer.initialize_agent_integrations()
    bus = initializer.build_event_bus()

    traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    request = _build_request()
    request.headers = {"traceparent": traceparent}

    await bus.send_middleware_event(
        event_type=EVENT_PENETRATION_ATTEMPT,
        request=request,
        action_taken="blocked",
        reason="with trace",
    )

    await initializer.shutdown_agent_integrations()

    spans = exporter.get_finished_spans()
    assert any(s.name == "guard.event.penetration_attempt" for s in spans)
    span = next(s for s in spans if s.name == "guard.event.penetration_attempt")
    # Parent span id should reflect the caller's span id from the traceparent.
    assert span.parent is not None
    assert f"{span.parent.span_id:016x}" == "b7ad6b7169203331"
    assert f"{span.parent.trace_id:032x}" == "0af7651916cd43dd8448eb211c80319c"
