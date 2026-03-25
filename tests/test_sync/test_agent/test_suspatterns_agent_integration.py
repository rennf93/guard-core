import logging
from collections.abc import Generator
from unittest.mock import MagicMock

import pytest

from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager


@pytest.fixture
def cleanup_suspatterns_singleton() -> Generator[None, None, None]:
    original_instance = SusPatternsManager._instance

    SusPatternsManager._instance = None

    yield

    if SusPatternsManager._instance is not None:
        SusPatternsManager._instance.custom_patterns.clear()  # type: ignore
        SusPatternsManager._instance.compiled_custom_patterns.clear()

        original_len = len(SusPatternsManager.patterns)
        while len(SusPatternsManager._instance.patterns) > original_len:
            SusPatternsManager._instance.patterns.pop()  # pragma: no cover
            SusPatternsManager._instance.compiled_patterns.pop()  # pragma: no cover

    SusPatternsManager._instance = original_instance


def test_initialize_agent(cleanup_suspatterns_singleton: None) -> None:
    SusPatternsManager._instance = None

    manager = SusPatternsManager()
    mock_agent = MagicMock()

    manager.initialize_agent(mock_agent)

    assert manager.agent_handler is mock_agent


def test_send_pattern_event_exception_handling(
    cleanup_suspatterns_singleton: None, caplog: pytest.LogCaptureFixture
) -> None:
    SusPatternsManager._instance = None

    manager = SusPatternsManager()
    mock_agent = MagicMock()
    mock_agent.send_event.side_effect = Exception("Network error")
    manager.agent_handler = mock_agent

    caplog.set_level(logging.ERROR, logger="fastapi_guard.handlers.suspatterns")

    manager._send_pattern_event(
        event_type="pattern_detected",
        ip_address="192.168.1.100",
        action_taken="blocked",
        reason="Suspicious pattern detected",
        extra_data="test",
    )

    assert "Failed to send pattern event to agent: Network error" in caplog.text


def test_detect_pattern_match_no_match(
    cleanup_suspatterns_singleton: None,
) -> None:
    SusPatternsManager._instance = None

    manager = SusPatternsManager()
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    content = "This is completely safe content with no suspicious patterns"
    ip_address = "192.168.1.100"

    result, matched_pattern = manager.detect_pattern_match(
        content, ip_address, "test_context"
    )

    assert result is False
    assert matched_pattern is None
    mock_agent.send_event.assert_not_called()


def test_add_pattern_with_agent_event(
    cleanup_suspatterns_singleton: None,
) -> None:
    SusPatternsManager._instance = None

    manager = SusPatternsManager()
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    pattern = r"malicious\d+"
    manager.add_pattern(pattern, custom=True)

    assert pattern in manager.custom_patterns

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "pattern_added"
    assert sent_event.ip_address == "system"
    assert sent_event.action_taken == "pattern_added"
    assert sent_event.reason == "Custom pattern added to detection system"
    assert sent_event.metadata["pattern"] == pattern
    assert sent_event.metadata["pattern_type"] == "custom"
    assert sent_event.metadata["total_patterns"] == 1


def test_remove_pattern_with_agent_event(
    cleanup_suspatterns_singleton: None,
) -> None:
    SusPatternsManager._instance = None

    manager = SusPatternsManager()
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    manager.custom_patterns.clear()
    manager.compiled_custom_patterns.clear()

    pattern = r"test_pattern\d+"
    manager.add_pattern(pattern, custom=True)

    mock_agent.reset_mock()

    result = manager.remove_pattern(pattern, custom=True)

    assert result is True
    assert pattern not in manager.custom_patterns

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "pattern_removed"
    assert sent_event.ip_address == "system"
    assert sent_event.action_taken == "pattern_removed"
    assert sent_event.reason == "Custom pattern removed from detection system"
    assert sent_event.metadata["pattern"] == pattern
    assert sent_event.metadata["pattern_type"] == "custom"
    assert sent_event.metadata["total_patterns"] == 0
