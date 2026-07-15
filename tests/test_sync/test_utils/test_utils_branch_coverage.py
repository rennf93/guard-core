import logging
from unittest.mock import MagicMock, patch

import pytest

from guard_core.sync.utils import (
    _build_log_message_for_suspicious,
    _check_blocked_countries,
    _check_json_fields,
    _extract_request_context,
    _is_trusted_proxy,
    _log_at_level,
    _log_country_check_result,
    detect_penetration_attempt,
)


def test_is_trusted_proxy_cidr_not_matching() -> None:
    assert _is_trusted_proxy("10.0.0.1", ["192.168.0.0/16"]) is False


def test_extract_request_context_missing_client_host() -> None:
    request = MagicMock()
    request.client_host = None
    request.method = "GET"
    request.url_full = "http://test/"
    request.headers = {}
    ctx = _extract_request_context(request)
    assert ctx["client_ip"] == "unknown"


def test_build_log_message_for_suspicious_passive_mode_no_trigger() -> None:
    context = {
        "client_ip": "1.2.3.4",
        "method": "GET",
        "url": "http://x/",
        "headers": {},
    }
    details, reason = _build_log_message_for_suspicious(
        context, reason="", passive_mode=True, trigger_info=""
    )
    assert "[PASSIVE MODE]" in details
    assert "Trigger" not in reason


def test_log_at_level_unknown_level_is_noop(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("guard_core.test.log_at_level_unknown")
    with caplog.at_level(logging.DEBUG, logger=logger.name):
        _log_at_level(logger, "NOPE", "test-msg")
    assert not caplog.records


def test_log_country_check_result_unknown_type_is_noop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG, logger="root"):
        _log_country_check_result("1.2.3.4", "US", "not_a_known_type", MagicMock())
    assert not any("1.2.3.4" in r.getMessage() for r in caplog.records)


def test_check_blocked_countries_country_not_blocked() -> None:
    config = MagicMock()
    config.blocked_countries = ["CN"]
    geo_ip = MagicMock()
    with patch(
        "guard_core.sync.utils.check_ip_country",
        new=MagicMock(return_value=False),
    ) as mock_check:

        def _async_false(*_a: object, **_kw: object) -> bool:
            return False

        mock_check.side_effect = _async_false
        result = _check_blocked_countries("1.2.3.4", config, geo_ip)
    assert result is True


def test_check_json_fields_ignores_non_string_entries() -> None:
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    with patch.object(sus_patterns_handler, "detect") as mock_detect:

        def _async_miss(*_a: object, **_kw: object) -> dict[str, object]:
            return {"is_threat": False, "threats": []}

        mock_detect.side_effect = _async_miss
        detected, trigger = _check_json_fields(
            {"k1": 123, "k2": None, "k3": ["a"]},
            context="test",
            client_ip="1.2.3.4",
            correlation_id="cid",
        )
    assert detected is False
    assert trigger == ""
    mock_detect.assert_not_called()


def test_detect_penetration_attempt_no_client_host() -> None:
    request = MagicMock()
    request.client_host = None
    request.query_params = {}
    request.url_path = "/"
    request.headers = {}

    def _body() -> bytes:
        return b""

    request.body = _body

    _dpa = detect_penetration_attempt(request)

    detected = _dpa.is_threat
    assert detected is False


def test_detect_penetration_attempt_excluded_header_skipped() -> None:
    request = MagicMock()
    request.client_host = "1.2.3.4"
    request.query_params = {}
    request.url_path = "/"
    # Excluded header with malicious-looking content — should be skipped.
    request.headers = {"User-Agent": "<script>alert(1)</script>"}

    def _body() -> bytes:
        return b""

    request.body = _body

    _dpa = detect_penetration_attempt(request)

    detected = _dpa.is_threat
    assert detected is False
