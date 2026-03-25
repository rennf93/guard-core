import ipaddress
import logging
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.sync.handlers.cloud_handler import CloudManager


@pytest.fixture(autouse=True)
def cleanup_cloud_singleton() -> Generator[Any, Any, Any]:
    original_instance = CloudManager._instance
    original_ip_ranges = None
    if original_instance:
        original_ip_ranges = {
            provider: ranges.copy()
            for provider, ranges in original_instance.ip_ranges.items()
        }

    CloudManager._instance = None

    def custom_new(cls: type[CloudManager]) -> CloudManager:
        if cls._instance is None:
            cls._instance = object.__new__(cls)
            cls._instance.ip_ranges = {
                "AWS": set(),
                "GCP": set(),
                "Azure": set(),
            }
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
            cls._instance.logger = logging.getLogger(__name__)
        return cls._instance

    with (
        patch.object(CloudManager, "__new__", custom_new),
        patch(
            "guard_core.sync.handlers.cloud_handler.SecurityEvent", create=True
        ) as mock_event,
    ):
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield

    CloudManager._instance = original_instance
    if original_instance and original_ip_ranges:
        original_instance.ip_ranges = original_ip_ranges


def test_initialize_agent() -> None:
    manager = CloudManager()
    mock_agent = MagicMock()

    manager.initialize_agent(mock_agent)

    assert manager.agent_handler is mock_agent


def test_get_cloud_provider_details_invalid_ip() -> None:
    manager = CloudManager()

    manager.ip_ranges["AWS"] = {ipaddress.ip_network("10.0.0.0/8")}

    result = manager.get_cloud_provider_details("not-an-ip-address")

    assert result is None


def test_send_cloud_detection_event_no_agent() -> None:
    manager = CloudManager()
    manager.agent_handler = None

    manager.send_cloud_detection_event(
        ip="192.168.1.1",
        provider="AWS",
        network="192.168.0.0/16",
        action_taken="request_blocked",
    )


def test_send_cloud_detection_event_with_agent() -> None:
    manager = CloudManager()
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    manager.send_cloud_detection_event(
        ip="192.168.1.100",
        provider="AWS",
        network="192.168.0.0/16",
        action_taken="request_blocked",
    )

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "cloud_blocked"
    assert sent_event.ip_address == "192.168.1.100"
    assert sent_event.action_taken == "request_blocked"
    assert sent_event.reason == "IP belongs to blocked cloud provider: AWS"
    assert sent_event.metadata["cloud_provider"] == "AWS"
    assert sent_event.metadata["network"] == "192.168.0.0/16"


def test_send_cloud_event_no_agent_handler() -> None:
    manager = CloudManager()
    manager.agent_handler = None

    manager._send_cloud_event(
        event_type="cloud_blocked",
        ip_address="192.168.1.1",
        action_taken="blocked",
        reason="test reason",
    )


def test_send_cloud_event_success() -> None:
    manager = CloudManager()
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    manager._send_cloud_event(
        event_type="cloud_blocked",
        ip_address="192.168.1.100",
        action_taken="request_blocked",
        reason="Cloud provider blocked",
        cloud_provider="GCP",
        network="10.0.0.0/8",
        extra_data="test",
    )

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "cloud_blocked"
    assert sent_event.ip_address == "192.168.1.100"
    assert sent_event.action_taken == "request_blocked"
    assert sent_event.reason == "Cloud provider blocked"
    assert sent_event.metadata["cloud_provider"] == "GCP"
    assert sent_event.metadata["network"] == "10.0.0.0/8"
    assert sent_event.metadata["extra_data"] == "test"


def test_send_cloud_event_exception_handling(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = CloudManager()
    mock_agent = MagicMock()
    mock_agent.send_event.side_effect = Exception("Network error")
    manager.agent_handler = mock_agent

    caplog.set_level(logging.ERROR)

    manager._send_cloud_event(
        event_type="cloud_blocked",
        ip_address="192.168.1.101",
        action_taken="blocked",
        reason="Test failure",
    )

    assert "Failed to send cloud event to agent: Network error" in caplog.text
