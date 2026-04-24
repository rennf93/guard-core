from typing import Literal
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.behavioral.context import BehavioralContext
from guard_core.core.behavioral.processor import BehavioralProcessor
from guard_core.decorators.base import RouteConfig
from guard_core.handlers.behavior_handler import BehaviorRule


def create_route_config_with_rules(rules: list[BehaviorRule]) -> RouteConfig:
    config = RouteConfig()
    config.behavior_rules = rules
    return config


@pytest.fixture
def mock_event_bus() -> Mock:
    event_bus = Mock()
    event_bus.send_middleware_event = AsyncMock()
    return event_bus


@pytest.fixture
def mock_guard_decorator() -> Mock:
    decorator = Mock()
    decorator.behavior_tracker = Mock()
    decorator.behavior_tracker.track_endpoint_usage = AsyncMock(return_value=False)
    decorator.behavior_tracker.track_return_pattern = AsyncMock(return_value=False)
    decorator.behavior_tracker.apply_action = AsyncMock()
    return decorator


@pytest.fixture
def behavioral_context(
    mock_event_bus: Mock, mock_guard_decorator: Mock
) -> BehavioralContext:
    context = BehavioralContext(
        config=Mock(),
        logger=Mock(),
        event_bus=mock_event_bus,
        guard_decorator=mock_guard_decorator,
    )
    return context


@pytest.fixture
def processor(behavioral_context: Mock) -> BehavioralProcessor:
    return BehavioralProcessor(behavioral_context)


@pytest.fixture
def mock_request() -> Mock:
    request = Mock()
    request.method = "GET"
    request.url_path = "/test"
    request.state = Mock()
    request.state.guard_endpoint_id = "test_module.test_function"
    request.state.guard_route_id = None
    return request


@pytest.fixture
def mock_response() -> Mock:
    response = Mock()
    response.status_code = 200
    return response


async def test_init(behavioral_context: Mock) -> None:
    processor = BehavioralProcessor(behavioral_context)
    assert processor.context == behavioral_context


async def test_process_usage_rules_no_decorator(
    processor: Mock, mock_request: Mock
) -> None:
    processor.context.guard_decorator = None
    route_config = RouteConfig()

    await processor.process_usage_rules(mock_request, "1.2.3.4", route_config)


async def test_process_usage_rules_no_threshold_exceeded(
    processor: Mock, mock_request: Mock
) -> None:
    rule = BehaviorRule(rule_type="usage", threshold=10, window=60, action="log")
    route_config = create_route_config_with_rules([rule])

    await processor.process_usage_rules(mock_request, "1.2.3.4", route_config)

    processor.context.guard_decorator.behavior_tracker.track_endpoint_usage.assert_called_once()
    processor.context.guard_decorator.behavior_tracker.apply_action.assert_not_called()


async def test_process_usage_rules_threshold_exceeded(
    processor: Mock, mock_request: Mock, mock_event_bus: Mock
) -> None:
    processor.context.guard_decorator.behavior_tracker.track_endpoint_usage = AsyncMock(
        return_value=True
    )

    rule = BehaviorRule(rule_type="usage", threshold=5, window=60, action="ban")
    route_config = create_route_config_with_rules([rule])

    await processor.process_usage_rules(mock_request, "1.2.3.4", route_config)

    mock_event_bus.send_middleware_event.assert_called_once()
    call_kwargs = mock_event_bus.send_middleware_event.call_args[1]
    assert call_kwargs["event_type"] == "decorator_violation"
    assert call_kwargs["action_taken"] == "behavioral_action_triggered"
    assert "threshold exceeded" in call_kwargs["reason"]
    assert call_kwargs["threshold"] == 5
    assert call_kwargs["window"] == 60

    processor.context.guard_decorator.behavior_tracker.apply_action.assert_called_once()


async def test_process_usage_rules_frequency_type(
    processor: Mock, mock_request: Mock
) -> None:
    processor.context.guard_decorator.behavior_tracker.track_endpoint_usage = AsyncMock(
        return_value=True
    )

    rule = BehaviorRule(rule_type="frequency", threshold=3, window=30, action="log")
    route_config = create_route_config_with_rules([rule])

    await processor.process_usage_rules(mock_request, "1.2.3.4", route_config)

    processor.context.guard_decorator.behavior_tracker.track_endpoint_usage.assert_called_once()
    processor.context.guard_decorator.behavior_tracker.apply_action.assert_called_once()


async def test_process_usage_rules_multiple_rules(
    processor: Mock, mock_request: Mock
) -> None:
    rule1 = BehaviorRule(rule_type="usage", threshold=5, window=60, action="log")
    rule2 = BehaviorRule(rule_type="frequency", threshold=10, window=30, action="ban")
    route_config = create_route_config_with_rules([rule1, rule2])

    await processor.process_usage_rules(mock_request, "1.2.3.4", route_config)

    assert (
        processor.context.guard_decorator.behavior_tracker.track_endpoint_usage.call_count
        == 2
    )


async def test_process_return_rules_no_decorator(
    processor: Mock, mock_request: Mock, mock_response: Mock
) -> None:
    processor.context.guard_decorator = None
    route_config = create_route_config_with_rules([])

    await processor.process_return_rules(
        mock_request, mock_response, "1.2.3.4", route_config
    )


async def test_process_return_rules_no_pattern_detected(
    processor: Mock, mock_request: Mock, mock_response: Mock
) -> None:
    rule = BehaviorRule(
        rule_type="return_pattern",
        pattern="error",
        threshold=3,
        window=60,
        action="log",
    )
    route_config = create_route_config_with_rules([rule])

    await processor.process_return_rules(
        mock_request, mock_response, "1.2.3.4", route_config
    )

    processor.context.guard_decorator.behavior_tracker.track_return_pattern.assert_called_once()
    processor.context.guard_decorator.behavior_tracker.apply_action.assert_not_called()


async def test_process_return_rules_pattern_detected(
    processor: Mock,
    mock_request: Mock,
    mock_response: Mock,
    mock_event_bus: Mock,
) -> None:
    processor.context.guard_decorator.behavior_tracker.track_return_pattern = AsyncMock(
        return_value=True
    )

    rule = BehaviorRule(
        rule_type="return_pattern",
        pattern="error",
        threshold=3,
        window=60,
        action="ban",
    )
    route_config = create_route_config_with_rules([rule])

    await processor.process_return_rules(
        mock_request, mock_response, "1.2.3.4", route_config
    )

    mock_event_bus.send_middleware_event.assert_called_once()
    call_kwargs = mock_event_bus.send_middleware_event.call_args[1]
    assert call_kwargs["event_type"] == "decorator_violation"
    assert call_kwargs["violation_type"] == "return_pattern"
    assert call_kwargs["pattern"] == "error"
    assert "Return pattern threshold exceeded" in call_kwargs["reason"]

    processor.context.guard_decorator.behavior_tracker.apply_action.assert_called_once()


async def test_process_return_rules_ignores_non_return_pattern(
    processor: Mock, mock_request: Mock, mock_response: Mock
) -> None:
    rule = BehaviorRule(
        rule_type="usage",
        threshold=5,
        window=60,
        action="log",
    )
    route_config = create_route_config_with_rules([rule])

    await processor.process_return_rules(
        mock_request, mock_response, "1.2.3.4", route_config
    )

    processor.context.guard_decorator.behavior_tracker.track_return_pattern.assert_not_called()


def test_get_endpoint_id_with_route(processor: Mock, mock_request: Mock) -> None:
    endpoint_id = processor.get_endpoint_id(mock_request)
    assert endpoint_id == "test_module.test_function"


def test_get_endpoint_id_no_guard_endpoint(processor: BehavioralProcessor) -> None:
    request = Mock()
    request.method = "POST"
    request.url_path = "/api/test"
    request.state = Mock(spec=[])

    endpoint_id = processor.get_endpoint_id(request)
    assert endpoint_id == "POST:/api/test"


def test_get_endpoint_id_none_state(processor: Mock) -> None:
    request = Mock()
    request.method = "GET"
    request.url_path = "/test"
    request.state = Mock()
    request.state.guard_endpoint_id = None

    endpoint_id = processor.get_endpoint_id(request)
    assert endpoint_id == "GET:/test"


@pytest.mark.parametrize(
    "rule_type,pattern,threshold,window,action",
    [
        ("usage", None, 5, 60, "log"),
        ("frequency", None, 10, 30, "ban"),
        ("return_pattern", "error", 3, 120, "alert"),
    ],
)
async def test_process_rules_with_various_configs(
    processor: Mock,
    mock_request: Mock,
    mock_response: Mock,
    rule_type: Literal["usage", "return_pattern", "frequency"],
    pattern: str | None,
    threshold: int,
    window: int,
    action: Literal["ban", "log", "throttle", "alert"],
) -> None:
    rule = BehaviorRule(
        rule_type=rule_type,
        pattern=pattern,
        threshold=threshold,
        window=window,
        action=action,
    )
    route_config = create_route_config_with_rules([rule])

    if rule_type in ["usage", "frequency"]:
        await processor.process_usage_rules(mock_request, "1.2.3.4", route_config)
        processor.context.guard_decorator.behavior_tracker.track_endpoint_usage.assert_called()
    else:
        await processor.process_return_rules(
            mock_request, mock_response, "1.2.3.4", route_config
        )
        processor.context.guard_decorator.behavior_tracker.track_return_pattern.assert_called()


async def test_process_usage_rules_skips_return_pattern_rules(
    processor: BehavioralProcessor,
    mock_request: Mock,
) -> None:
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=5,
        pattern="status:404",
    )
    route_config = create_route_config_with_rules([rule])
    await processor.process_usage_rules(mock_request, "1.2.3.4", route_config)
    tracker = processor.context.guard_decorator.behavior_tracker
    tracker.track_endpoint_usage.assert_not_called()
