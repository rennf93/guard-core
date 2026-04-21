import logging
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.sync.handlers.ipinfo_handler import IPInfoManager


@pytest.fixture
def cleanup_ipinfo_singleton() -> Generator[Any, Any, Any]:
    IPInfoManager._instance = None

    def custom_new(
        cls: type[IPInfoManager], token: str, db_path: Path | None = None
    ) -> IPInfoManager:
        if cls._instance is None:
            cls._instance = object.__new__(cls)
            cls._instance.token = token
            cls._instance.db_path = db_path or Path("data/ipinfo/country_asn.mmdb")
            cls._instance.reader = None
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
            cls._instance.logger = logging.getLogger(__name__)

        cls._instance.token = token
        if db_path is not None:
            cls._instance.db_path = db_path
        return cls._instance

    with (
        patch.object(IPInfoManager, "__new__", custom_new),
        patch(
            "guard_core.sync.handlers.ipinfo_handler.SecurityEvent",
            create=True,
        ) as mock_event,
    ):
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield

    IPInfoManager._instance = None


def test_initialize_agent(cleanup_ipinfo_singleton: None) -> None:
    manager = IPInfoManager(token="test-token")
    mock_agent = MagicMock()

    manager.initialize_agent(mock_agent)

    assert manager.agent_handler is mock_agent


def test_send_geo_event_no_agent_handler(
    cleanup_ipinfo_singleton: None,
) -> None:
    manager = IPInfoManager(token="test-token")
    manager.agent_handler = None

    manager._send_geo_event(
        event_type="geo_lookup_failed",
        ip_address="192.168.1.1",
        action_taken="blocked",
        reason="test reason",
    )


def test_send_geo_event_success(cleanup_ipinfo_singleton: None) -> None:
    manager = IPInfoManager(token="test-token")
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    manager._send_geo_event(
        event_type="country_blocked",
        ip_address="192.168.1.100",
        action_taken="request_blocked",
        reason="Country not allowed",
        country="CN",
        rule_type="country_blacklist",
    )

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "country_blocked"
    assert sent_event.ip_address == "192.168.1.100"
    assert sent_event.action_taken == "request_blocked"
    assert sent_event.reason == "Country not allowed"
    assert sent_event.metadata["country"] == "CN"
    assert sent_event.metadata["rule_type"] == "country_blacklist"


def test_send_geo_event_exception_handling(
    cleanup_ipinfo_singleton: None, caplog: pytest.LogCaptureFixture
) -> None:
    manager = IPInfoManager(token="test-token")
    mock_agent = MagicMock()
    mock_agent.send_event.side_effect = Exception("Network error")
    manager.agent_handler = mock_agent

    caplog.set_level(logging.ERROR)

    manager._send_geo_event(
        event_type="geo_lookup_failed",
        ip_address="192.168.1.101",
        action_taken="lookup_failed",
        reason="Test failure",
    )

    assert "Failed to send geo event to agent: Network error" in caplog.text


def test_initialize_database_download_failure_with_agent(
    cleanup_ipinfo_singleton: None,
) -> None:
    manager = IPInfoManager(token="test-token", db_path=Path("test_data/test.mmdb"))
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    with patch.object(manager, "_download_database") as mock_download:
        mock_download.side_effect = Exception("Download failed")

        with patch.object(manager, "_is_db_outdated", return_value=True):
            manager.initialize()

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "geo_lookup_failed"
    assert sent_event.ip_address == "system"
    assert sent_event.action_taken == "database_download_failed"
    assert "Failed to download IPInfo database" in sent_event.reason


def test_get_country_exception_with_agent(
    cleanup_ipinfo_singleton: None,
) -> None:
    manager = IPInfoManager(token="test-token")
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    mock_reader = MagicMock()
    mock_reader.get.side_effect = Exception("Database corrupted")
    manager.reader = mock_reader

    result = manager.get_country("192.168.1.100")
    assert result is None

    time.sleep(0.1)

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "geo_lookup_failed"
    assert sent_event.ip_address == "192.168.1.100"
    assert sent_event.action_taken == "lookup_failed"
    assert "Geographic lookup failed: Database corrupted" in sent_event.reason


def test_get_country_exception_no_agent(
    cleanup_ipinfo_singleton: None,
) -> None:
    manager = IPInfoManager(token="test-token")
    manager.agent_handler = None

    mock_reader = MagicMock()
    mock_reader.get.side_effect = Exception("Database error")
    manager.reader = mock_reader

    result = manager.get_country("192.168.1.100")
    assert result is None


def test_check_country_access_no_country(
    cleanup_ipinfo_singleton: None,
) -> None:
    manager = IPInfoManager(token="test-token")
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    mock_reader = MagicMock()
    mock_reader.get.return_value = None
    manager.reader = mock_reader

    result, country = manager.check_country_access(
        "192.168.1.100",
        blocked_countries=["CN", "RU"],
        whitelist_countries=None,
    )

    assert result is True
    assert country is None
    mock_agent.send_event.assert_not_called()


def test_check_country_access_no_country_with_whitelist(
    cleanup_ipinfo_singleton: None,
) -> None:
    manager = IPInfoManager(token="test-token")
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    mock_reader = MagicMock()
    mock_reader.get.return_value = None
    manager.reader = mock_reader

    result, country = manager.check_country_access(
        "192.168.1.100",
        blocked_countries=["CN", "RU"],
        whitelist_countries=["US", "GB"],
    )

    assert result is False
    assert country is None


def test_check_country_access_whitelist_not_in_list(
    cleanup_ipinfo_singleton: None,
) -> None:
    manager = IPInfoManager(token="test-token")
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    with patch.object(manager, "get_country", return_value="CN"):
        result, country = manager.check_country_access(
            "192.168.1.100",
            blocked_countries=[],
            whitelist_countries=["US", "CA", "GB"],
        )

    assert result is False
    assert country == "CN"

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "country_blocked"
    assert sent_event.ip_address == "192.168.1.100"
    assert sent_event.action_taken == "request_blocked"
    assert sent_event.reason == "Country CN not in allowed list"
    assert sent_event.metadata["country"] == "CN"
    assert sent_event.metadata["rule_type"] == "country_whitelist"


def test_check_country_access_blacklist_blocked(
    cleanup_ipinfo_singleton: None,
) -> None:
    manager = IPInfoManager(token="test-token")
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    with patch.object(manager, "get_country", return_value="RU"):
        result, country = manager.check_country_access(
            "192.168.1.100",
            blocked_countries=["CN", "RU", "KP"],
            whitelist_countries=None,
        )

    assert result is False
    assert country == "RU"

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "country_blocked"
    assert sent_event.ip_address == "192.168.1.100"
    assert sent_event.action_taken == "request_blocked"
    assert sent_event.reason == "Country RU is blocked"
    assert sent_event.metadata["country"] == "RU"
    assert sent_event.metadata["rule_type"] == "country_blacklist"


def test_check_country_access_allowed(
    cleanup_ipinfo_singleton: None,
) -> None:
    manager = IPInfoManager(token="test-token")
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    with patch.object(manager, "get_country", return_value="US"):
        result, country = manager.check_country_access(
            "192.168.1.100",
            blocked_countries=["CN", "RU"],
            whitelist_countries=None,
        )

    assert result is True
    assert country == "US"

    mock_agent.send_event.assert_not_called()


def test_check_country_access_whitelist_in_list(
    cleanup_ipinfo_singleton: None,
) -> None:
    manager = IPInfoManager(token="test-token")
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    with patch.object(manager, "get_country", return_value="US"):
        result, country = manager.check_country_access(
            "192.168.1.100",
            blocked_countries=["CN", "RU"],
            whitelist_countries=["US", "CA", "GB"],
        )

    assert result is True
    assert country == "US"

    mock_agent.send_event.assert_not_called()
