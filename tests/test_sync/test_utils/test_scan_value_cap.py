import logging

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_SQLI_PAYLOAD = "1 OR 1=1 UNION SELECT password FROM users--"


def _query_request(
    params: dict[str, str], client_host: str = "127.0.0.1"
) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(query_params=params, client_host=client_host)


def test_payload_within_the_cap_is_still_detected() -> None:
    config = SecurityConfig(detection_max_scan_values=2)
    request = _query_request({"q": _SQLI_PAYLOAD})

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is True


def test_payload_past_the_cap_is_not_scanned() -> None:
    config = SecurityConfig(detection_max_scan_values=2)
    params = {f"pad{i}": "benign" for i in range(20)}
    params["payload"] = _SQLI_PAYLOAD
    request = _query_request(params)

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is False


def test_cap_reached_logs_a_single_warning_naming_the_client_ip(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(detection_max_scan_values=2)
    params = {f"pad{i}": "benign" for i in range(20)}
    params["payload"] = _SQLI_PAYLOAD
    request = _query_request(params, client_host="203.0.113.77")

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        detect_penetration_attempt(request, config)

    assert caplog.text.count("detection_max_scan_values") == 1
    assert "203.0.113.77" in caplog.text


def test_scan_value_budget_resets_between_requests(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(detection_max_scan_values=2)
    params = {f"pad{i}": "benign" for i in range(20)}
    params["payload"] = _SQLI_PAYLOAD
    request = _query_request(params)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        detect_penetration_attempt(request, config)
        detect_penetration_attempt(request, config)

    assert caplog.text.count("detection_max_scan_values") == 2


def test_default_cap_never_trips_on_an_ordinary_request(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = _query_request({"q": _SQLI_PAYLOAD})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, SecurityConfig())

    assert result.is_threat is True
    assert "detection_max_scan_values" not in caplog.text


def test_config_none_still_uses_the_default_cap(
    caplog: pytest.LogCaptureFixture,
) -> None:
    params = {f"pad{i}": "benign" for i in range(600)}
    request = _query_request(params)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request)

    assert result.is_threat is False
    assert "detection_max_scan_values" in caplog.text
