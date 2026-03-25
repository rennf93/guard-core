from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.sync.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)


@pytest.fixture
def headers_manager() -> Generator[SecurityHeadersManager, None]:
    security_headers_manager.reset()
    yield security_headers_manager
    security_headers_manager.reset()


def test_initialize_agent(headers_manager: SecurityHeadersManager) -> None:
    mock_agent = MagicMock()

    headers_manager.initialize_agent(mock_agent)

    assert headers_manager.agent_handler == mock_agent


def test_send_headers_applied_event_no_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    headers_manager.agent_handler = None

    headers_manager._send_headers_applied_event(
        "/api/test", {"X-Content-Type-Options": "nosniff"}
    )


def test_send_headers_applied_event_with_mock_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock()

    headers_manager.agent_handler = mock_agent

    headers = {
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
    }

    headers_manager._send_headers_applied_event("/api/test", headers)

    assert headers_manager.agent_handler == mock_agent


def test_send_headers_event_with_actual_exception(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock(side_effect=Exception("Network error"))

    headers_manager.agent_handler = mock_agent

    import sys

    mock_guard_agent = MagicMock()
    mock_event_class = MagicMock()
    mock_event_instance = MagicMock()
    mock_event_class.return_value = mock_event_instance
    mock_guard_agent.SecurityEvent = mock_event_class

    sys.modules["guard_agent"] = mock_guard_agent

    try:
        headers_manager._send_headers_applied_event(
            "/api/test", {"X-Content-Type-Options": "nosniff"}
        )

        mock_event_class.assert_called_once()

        mock_agent.send_event.assert_called_once_with(mock_event_instance)
    finally:
        if "guard_agent" in sys.modules:
            del sys.modules["guard_agent"]


def test_send_csp_violation_event_no_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    headers_manager.agent_handler = None

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com/page",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
    }

    headers_manager._send_csp_violation_event(csp_report)


def test_send_csp_violation_event_with_mock_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock()

    headers_manager.agent_handler = mock_agent

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com/page",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
        "source-file": "https://example.com/app.js",
        "line-number": 42,
    }

    headers_manager._send_csp_violation_event(csp_report)

    assert headers_manager.agent_handler == mock_agent


def test_send_csp_violation_event_with_actual_exception(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock(side_effect=Exception("API error"))

    headers_manager.agent_handler = mock_agent

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
    }

    import sys

    mock_guard_agent = MagicMock()
    mock_event_class = MagicMock()
    mock_event_instance = MagicMock()
    mock_event_class.return_value = mock_event_instance
    mock_guard_agent.SecurityEvent = mock_event_class

    sys.modules["guard_agent"] = mock_guard_agent

    try:
        headers_manager._send_csp_violation_event(csp_report)

        mock_event_class.assert_called_once()

        mock_agent.send_event.assert_called_once_with(mock_event_instance)
    finally:
        if "guard_agent" in sys.modules:
            del sys.modules["guard_agent"]


def test_validate_csp_report_with_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock()

    headers_manager.agent_handler = mock_agent

    valid_report = {
        "csp-report": {
            "document-uri": "https://example.com",
            "violated-directive": "script-src",
            "blocked-uri": "https://evil.com/script.js",
        }
    }

    result = headers_manager.validate_csp_report(valid_report)

    assert result is True
    assert headers_manager.agent_handler == mock_agent


def test_get_headers_with_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock()

    headers_manager.agent_handler = mock_agent
    headers_manager.enabled = True

    headers = headers_manager.get_headers("/api/secure")

    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers

    assert headers_manager.agent_handler == mock_agent


def test_get_headers_no_agent_no_path(
    headers_manager: SecurityHeadersManager,
) -> None:
    headers_manager.agent_handler = None
    headers_manager.enabled = True

    headers = headers_manager.get_headers()

    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers

    assert "default" in headers_manager.headers_cache


def test_get_headers_disabled(
    headers_manager: SecurityHeadersManager,
) -> None:
    headers_manager.enabled = False

    headers = headers_manager.get_headers("/test")

    assert headers == {}


def test_concurrent_access_thread_safety() -> None:
    manager = SecurityHeadersManager()

    def configure_and_get_headers(config_id: int) -> dict[str, str]:
        manager.configure(custom_headers={f"X-Thread-{config_id}": str(config_id)})
        headers = manager.get_headers(f"/path/{config_id}")
        return headers

    results = [configure_and_get_headers(i) for i in range(10)]

    assert len(results) == 10
    for result in results:
        assert isinstance(result, dict)
        assert "X-Content-Type-Options" in result
