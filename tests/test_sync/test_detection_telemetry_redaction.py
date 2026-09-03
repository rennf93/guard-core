import json
import logging
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync._utils.detection_scan import _json_depth_cap_value
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_SQLI_PAYLOAD = "' OR 1=1--"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


@pytest.fixture
def mock_agent() -> Iterator[MagicMock]:
    agent = MagicMock()
    agent.send_event = MagicMock()
    sus_patterns_handler.agent_handler = agent
    try:
        yield agent
    finally:
        sus_patterns_handler.agent_handler = None


def _json_request(body: bytes) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )


def _nested_wrapper_body(depth: int, wrapper_key: str, leaf: dict) -> bytes:
    leaf_json = json.dumps(leaf)
    prefix = f'{{"{wrapper_key}":' * depth
    suffix = "}" * depth
    return (prefix + leaf_json + suffix).encode()


def _single_threat_event_metadata(mock_agent: MagicMock) -> dict[str, Any]:
    pattern_detected_calls = [
        call
        for call in mock_agent.send_event.call_args_list
        if getattr(call.args[0], "event_type", None) == "pattern_detected"
    ]
    assert len(pattern_detected_calls) == 1, (
        f"expected exactly one pattern_detected event, "
        f"got {len(pattern_detected_calls)}"
    )
    return dict(pattern_detected_calls[0].args[0].metadata)


def test_sensitive_header_threat_event_content_preview_redacted(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig(log_sensitive_headers={"x-session"})
    secret = "tok-SECRET-EVENT"
    request = SyncMockGuardRequest(
        headers={"X-Session": f"{secret} <script>alert(1)</script>"},
    )

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert secret not in json.dumps(metadata, default=str)


def test_sensitive_query_param_threat_event_content_preview_redacted(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    secret = "SECRET-EVENT-Q"
    request = SyncMockGuardRequest(
        query_params={"token": f"{secret} <script>alert(1)</script>"},
    )

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert secret not in json.dumps(metadata, default=str)


_EMBEDDED_JSON_SECRET = "SECRET-EMB"
_EMBEDDED_JSON_PAYLOAD = json.dumps(
    {"q": "<script>alert(1)</script>", "tok": _EMBEDDED_JSON_SECRET}
)


def test_sensitive_header_embedded_json_field_content_preview_redacted(
    mock_agent: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(log_sensitive_headers={"x-session"})
    request = SyncMockGuardRequest(headers={"X-Session": _EMBEDDED_JSON_PAYLOAD})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert _EMBEDDED_JSON_SECRET not in json.dumps(metadata, default=str)
    assert _EMBEDDED_JSON_SECRET not in caplog.text


def test_sensitive_query_param_embedded_json_field_content_preview_redacted(
    mock_agent: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig()
    request = SyncMockGuardRequest(query_params={"token": _EMBEDDED_JSON_PAYLOAD})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert _EMBEDDED_JSON_SECRET not in json.dumps(metadata, default=str)
    assert _EMBEDDED_JSON_SECRET not in caplog.text


def test_non_sensitive_header_embedded_json_field_content_preview_is_raw(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    request = SyncMockGuardRequest(headers={"X-Custom": _EMBEDDED_JSON_PAYLOAD})

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "<script>alert(1)</script>"


def _single_threat_event(mock_agent: MagicMock) -> Any:
    pattern_detected_calls = [
        call
        for call in mock_agent.send_event.call_args_list
        if getattr(call.args[0], "event_type", None) == "pattern_detected"
    ]
    assert len(pattern_detected_calls) == 1, (
        f"expected exactly one pattern_detected event, "
        f"got {len(pattern_detected_calls)}"
    )
    return pattern_detected_calls[0].args[0]


_EMBEDDED_JSON_SECRET_KEY = "SECRET-KEY-<script>alert(1)</script>"


def test_sensitive_query_param_embedded_json_key_redacted_in_reason(
    mock_agent: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(log_sensitive_params={"tok"})
    payload = json.dumps({_EMBEDDED_JSON_SECRET_KEY: "benign"})
    request = SyncMockGuardRequest(query_params={"tok": payload})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    event = _single_threat_event(mock_agent)
    dumped_metadata = json.dumps(dict(event.metadata), default=str)
    assert "SECRET-KEY" not in event.reason
    assert "SECRET-KEY" not in dumped_metadata
    assert "SECRET-KEY" not in caplog.text
    assert "[REDACTED]" in event.reason
    assert "[REDACTED]" in dumped_metadata


def test_sensitive_header_embedded_json_key_redacted_in_reason(
    mock_agent: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(log_sensitive_headers={"x-session"})
    payload = json.dumps({_EMBEDDED_JSON_SECRET_KEY: "benign"})
    request = SyncMockGuardRequest(headers={"X-Session": payload})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    event = _single_threat_event(mock_agent)
    dumped_metadata = json.dumps(dict(event.metadata), default=str)
    assert "SECRET-KEY" not in event.reason
    assert "SECRET-KEY" not in dumped_metadata
    assert "SECRET-KEY" not in caplog.text
    assert "[REDACTED]" in event.reason
    assert "[REDACTED]" in dumped_metadata


def test_non_sensitive_query_param_embedded_json_key_reports_raw_key_in_context(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    payload = json.dumps({_EMBEDDED_JSON_SECRET_KEY: "benign"})
    request = SyncMockGuardRequest(query_params={"q": payload})

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert _EMBEDDED_JSON_SECRET_KEY in metadata["context"]


def test_sensitive_body_field_threat_event_content_preview_redacted(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    secret = "SECRET-EVENT-BODY"
    body = json.dumps({"password": f"{secret} {_SQLI_PAYLOAD}"}).encode()

    result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert secret not in json.dumps(metadata, default=str)


def test_non_sensitive_query_param_embedded_json_sensitive_field_preview_redacted(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    secret = "SECRET-EMBEDDED-FIELD"
    body = json.dumps({"password": f"{secret} {_SQLI_PAYLOAD}", "note": "benign"})
    request = SyncMockGuardRequest(query_params={"data": body})

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert secret not in json.dumps(metadata, default=str)


def test_capped_json_subtree_threat_event_preview_matches_redacted_display(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    depth = _json_depth_cap_value() - 1
    secret = "SECRET-EVENT-NESTED"
    leaf = {"password": f"{secret} {_SQLI_PAYLOAD}"}
    body = _nested_wrapper_body(depth, "wrapper", leaf)

    result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    expected_display = json.dumps(
        {"password": "[REDACTED]"}, separators=(",", ":"), ensure_ascii=False
    )
    assert metadata["content_preview"] == expected_display
    assert secret not in json.dumps(metadata, default=str)


def test_non_sensitive_query_param_threat_event_content_preview_is_raw(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    payload = "<script>alert(1)</script>"
    request = SyncMockGuardRequest(query_params={"q": payload})

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == payload


def test_non_sensitive_long_query_param_threat_event_content_preview_capped(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    payload = ("A" * 91) + _SQLI_PAYLOAD
    assert len(payload) > 100
    request = SyncMockGuardRequest(query_params={"q": payload})

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == payload[:100]


def test_detect_uses_content_preview_kwarg_over_raw_content_for_event(
    mock_agent: MagicMock,
) -> None:
    secret = "SECRET-DIRECT"
    payload = f"{secret} {_SQLI_PAYLOAD}"

    result = sus_patterns_handler.detect(
        content=payload,
        ip_address="127.0.0.1",
        context="unit_test",
        content_preview="[REDACTED]",
    )

    assert result["is_threat"] is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert secret not in json.dumps(metadata, default=str)


def test_detect_content_preview_still_capped_at_100_chars(
    mock_agent: MagicMock,
) -> None:
    long_preview = "P" * 150

    result = sus_patterns_handler.detect(
        content=_SQLI_PAYLOAD,
        ip_address="127.0.0.1",
        context="unit_test",
        content_preview=long_preview,
    )

    assert result["is_threat"] is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "P" * 100
