from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.core.events.event_types import (
    EVENT_CLOUD_BLOCKED,
    EVENT_PENETRATION_ATTEMPT,
    EventFilter,
)
from guard_core.core.events.middleware_events import SecurityEventBus


@pytest.fixture
def config() -> MagicMock:
    cfg = MagicMock()
    cfg.agent_enable_events = True
    return cfg


@pytest.fixture
def agent_handler() -> AsyncMock:
    return AsyncMock()


def _make_request() -> MagicMock:
    request = MagicMock()
    request.client_host = "1.2.3.4"
    request.headers = {"User-Agent": "test"}
    request.url_path = "/test"
    request.method = "GET"
    return request


async def test_event_bus_mutes_filtered_event_type(
    config: MagicMock, agent_handler: AsyncMock
) -> None:
    bus = SecurityEventBus(
        agent_handler=agent_handler,
        config=config,
        event_filter=EventFilter(
            muted_event_types=frozenset({EVENT_CLOUD_BLOCKED}),
        ),
    )
    request = _make_request()
    await bus.send_middleware_event(
        event_type=EVENT_CLOUD_BLOCKED,
        request=request,
        action_taken="blocked",
        reason="test",
    )
    agent_handler.send_event.assert_not_awaited()


async def test_event_bus_sends_non_muted_event_type(
    config: MagicMock, agent_handler: AsyncMock
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
            "guard_core.core.events.middleware_events.extract_client_ip",
            return_value="1.2.3.4",
        ),
        patch(
            "guard_core.core.events.middleware_events.get_pipeline_response_time",
            return_value=0.1,
        ),
    ):
        await bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="blocked",
            reason="test",
        )
    agent_handler.send_event.assert_awaited_once()


async def test_event_bus_no_filter_defaults_to_allow_all(
    config: MagicMock, agent_handler: AsyncMock
) -> None:
    bus = SecurityEventBus(
        agent_handler=agent_handler,
        config=config,
    )
    request = _make_request()
    with (
        patch(
            "guard_core.core.events.middleware_events.extract_client_ip",
            return_value="1.2.3.4",
        ),
        patch(
            "guard_core.core.events.middleware_events.get_pipeline_response_time",
            return_value=0.1,
        ),
    ):
        await bus.send_middleware_event(
            event_type=EVENT_CLOUD_BLOCKED,
            request=request,
            action_taken="blocked",
            reason="test",
        )
    agent_handler.send_event.assert_awaited_once()


async def test_event_bus_allows_all_with_empty_filter(
    config: MagicMock, agent_handler: AsyncMock
) -> None:
    bus = SecurityEventBus(
        agent_handler=agent_handler,
        config=config,
        event_filter=EventFilter(),
    )
    request = _make_request()
    with (
        patch(
            "guard_core.core.events.middleware_events.extract_client_ip",
            return_value="1.2.3.4",
        ),
        patch(
            "guard_core.core.events.middleware_events.get_pipeline_response_time",
            return_value=0.1,
        ),
    ):
        await bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="blocked",
            reason="test",
        )
    agent_handler.send_event.assert_awaited_once()
