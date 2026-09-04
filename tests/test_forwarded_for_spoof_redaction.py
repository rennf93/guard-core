import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.models import SecurityConfig
from guard_core.utils import extract_client_ip
from tests.conftest import MockGuardRequest

_SECRET = "SECRET-XFF-SPOOF-LEAK"


def _untrusted_request(xff_value: str) -> MockGuardRequest:
    return MockGuardRequest(
        client_host="9.9.9.9",
        headers={"X-Forwarded-For": xff_value},
    )


def _config() -> SecurityConfig:
    return SecurityConfig(trusted_proxies=["10.0.0.1"])


async def test_spoofed_json_xff_redacted_in_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    xff_value = f'{{"password": "{_SECRET}"}}'
    request = _untrusted_request(xff_value)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        await extract_client_ip(request, _config())

    assert "[REDACTED]" in caplog.text
    assert _SECRET not in caplog.text


async def test_spoofed_json_xff_redacted_in_event_reason() -> None:
    xff_value = f'{{"password": "{_SECRET}"}}'
    request = _untrusted_request(xff_value)
    agent = MagicMock()
    agent.send_event = AsyncMock()

    await extract_client_ip(request, _config(), agent_handler=agent)

    assert agent.send_event.call_count == 1
    event = agent.send_event.call_args_list[0].args[0]
    assert "[REDACTED]" in event.reason
    assert _SECRET not in event.reason


async def test_legitimate_ip_only_xff_chain_shown_unchanged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    xff_value = "10.0.0.5, 203.0.113.9"
    request = _untrusted_request(xff_value)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        await extract_client_ip(request, _config())

    assert xff_value in caplog.text
    assert "[REDACTED]" not in caplog.text


async def test_legitimate_ip_only_xff_chain_event_reason_unchanged() -> None:
    xff_value = "10.0.0.5, 203.0.113.9"
    request = _untrusted_request(xff_value)
    agent = MagicMock()
    agent.send_event = AsyncMock()

    await extract_client_ip(request, _config(), agent_handler=agent)

    assert agent.send_event.call_count == 1
    event = agent.send_event.call_args_list[0].args[0]
    assert xff_value in event.reason
    assert "[REDACTED]" not in event.reason


async def test_mixed_valid_and_spoofed_xff_chain_partially_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    xff_value = f"10.0.0.5, {_SECRET}"
    request = _untrusted_request(xff_value)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        await extract_client_ip(request, _config())

    assert "10.0.0.5" in caplog.text
    assert "[REDACTED]" in caplog.text
    assert _SECRET not in caplog.text
