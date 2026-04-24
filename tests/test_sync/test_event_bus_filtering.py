from unittest.mock import MagicMock, patch

import pytest

from guard_core.sync.core.events.event_types import (
    EVENT_CLOUD_BLOCKED,
    EVENT_PENETRATION_ATTEMPT,
    EventFilter,
)
from guard_core.sync.core.events.middleware_events import SecurityEventBus


@pytest.fixture
def config() -> MagicMock:
    cfg = MagicMock()
    cfg.agent_enable_events = True
    return cfg


@pytest.fixture
def agent_handler() -> MagicMock:
    return MagicMock()


def _make_request() -> MagicMock:
    request = MagicMock()
    request.client_host = "1.2.3.4"
    request.headers = {"User-Agent": "test"}
    request.url_path = "/test"
    request.method = "GET"
    return request


def test_event_bus_mutes_filtered_event_type(
    config: MagicMock, agent_handler: MagicMock
) -> None:
    bus = SecurityEventBus(
        agent_handler=agent_handler,
        config=config,
        event_filter=EventFilter(
            muted_event_types=frozenset({EVENT_CLOUD_BLOCKED}),
        ),
    )
    request = _make_request()
    bus.send_middleware_event(
        event_type=EVENT_CLOUD_BLOCKED,
        request=request,
        action_taken="blocked",
        reason="test",
    )
    agent_handler.send_event.assert_not_called()


def test_event_bus_sends_non_muted_event_type(
    config: MagicMock, agent_handler: MagicMock
) -> None:
    bus = SecurityEventBus(
        agent_handler=agent_handler,
        config=config,
        event_filter=EventFilter(
            muted_event_types=frozenset({EVENT_CLOUD_BLOCKED}),
        ),
    )
    request = _make_request()
    with (
        patch(
            "guard_core.sync.core.events.middleware_events.extract_client_ip",
            return_value="1.2.3.4",
        ),
        patch(
            "guard_core.sync.core.events.middleware_events.get_pipeline_response_time",
            return_value=0.1,
        ),
    ):
        bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="blocked",
            reason="test",
        )
    agent_handler.send_event.assert_called_once()


def test_event_bus_no_filter_defaults_to_allow_all(
    config: MagicMock, agent_handler: MagicMock
) -> None:
    bus = SecurityEventBus(
        agent_handler=agent_handler,
        config=config,
    )
    request = _make_request()
    with (
        patch(
            "guard_core.sync.core.events.middleware_events.extract_client_ip",
            return_value="1.2.3.4",
        ),
        patch(
            "guard_core.sync.core.events.middleware_events.get_pipeline_response_time",
            return_value=0.1,
        ),
    ):
        bus.send_middleware_event(
            event_type=EVENT_CLOUD_BLOCKED,
            request=request,
            action_taken="blocked",
            reason="test",
        )
    agent_handler.send_event.assert_called_once()


def test_event_bus_allows_all_with_empty_filter(
    config: MagicMock, agent_handler: MagicMock
) -> None:
    bus = SecurityEventBus(
        agent_handler=agent_handler,
        config=config,
        event_filter=EventFilter(),
    )
    request = _make_request()
    with (
        patch(
            "guard_core.sync.core.events.middleware_events.extract_client_ip",
            return_value="1.2.3.4",
        ),
        patch(
            "guard_core.sync.core.events.middleware_events.get_pipeline_response_time",
            return_value=0.1,
        ),
    ):
        bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="blocked",
            reason="test",
        )
    agent_handler.send_event.assert_called_once()


def test_event_bus_attaches_traceparent_from_request_headers(
    config: MagicMock,
) -> None:
    captured: dict[str, object] = {}

    def capture_send(event):
        captured["event"] = event

    agent = MagicMock()
    agent.send_event = capture_send

    bus = SecurityEventBus(agent_handler=agent, config=config)

    request = MagicMock()
    request.client_host = "1.2.3.4"
    request.headers = {
        "User-Agent": "test",
        "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
    }
    request.url_path = "/x"
    request.method = "GET"

    from types import SimpleNamespace

    fake_event_cls = MagicMock(side_effect=lambda **kw: SimpleNamespace(**kw))
    with (
        patch(
            "guard_core.sync.core.events.middleware_events.extract_client_ip",
            return_value="1.2.3.4",
        ),
        patch(
            "guard_core.sync.core.events.middleware_events.SecurityEvent",
            fake_event_cls,
            create=True,
        ),
        patch(
            "guard_core.sync.core.events.middleware_events.get_pipeline_response_time",
            return_value=0.0,
        ),
    ):
        bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="blocked",
            reason="test",
        )

    event = captured["event"]
    assert (
        event.metadata["traceparent"]
        == "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    )


def test_event_bus_attaches_tracestate_from_request_headers(config: MagicMock) -> None:
    captured: dict[str, object] = {}

    def capture_send(event):
        captured["event"] = event

    agent = MagicMock()
    agent.send_event = capture_send

    bus = SecurityEventBus(agent_handler=agent, config=config)

    request = MagicMock()
    request.client_host = "1.2.3.4"
    request.headers = {
        "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        "tracestate": "vendor=xyz",
    }
    request.url_path = "/x"
    request.method = "GET"

    from types import SimpleNamespace

    fake_event_cls = MagicMock(side_effect=lambda **kw: SimpleNamespace(**kw))
    with (
        patch(
            "guard_core.sync.core.events.middleware_events.extract_client_ip",
            return_value="1.2.3.4",
        ),
        patch(
            "guard_core.sync.core.events.middleware_events.SecurityEvent",
            fake_event_cls,
            create=True,
        ),
        patch(
            "guard_core.sync.core.events.middleware_events.get_pipeline_response_time",
            return_value=0.0,
        ),
    ):
        bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="blocked",
            reason="test",
        )

    event = captured["event"]
    assert event.metadata["tracestate"] == "vendor=xyz"
