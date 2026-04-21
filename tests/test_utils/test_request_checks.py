import logging
import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from pytest_mock import MockerFixture

from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import (
    check_ip_country,
    detect_penetration_attempt,
    is_ip_allowed,
    is_user_agent_allowed,
)
from tests.conftest import MockGuardRequest

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))


async def test_is_ip_allowed(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    mocker.patch("guard_core.utils.check_ip_country", return_value=False)

    assert await is_ip_allowed("127.0.0.1", security_config)
    assert not await is_ip_allowed("192.168.1.1", security_config)

    empty_config = SecurityConfig(ipinfo_token=IPINFO_TOKEN, whitelist=[], blacklist=[])
    assert await is_ip_allowed("127.0.0.1", empty_config)
    assert await is_ip_allowed("192.168.1.1", empty_config)

    whitelist_config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, whitelist=["127.0.0.1"]
    )
    assert await is_ip_allowed("127.0.0.1", whitelist_config)
    assert not await is_ip_allowed("192.168.1.1", whitelist_config)

    blacklist_config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, blacklist=["192.168.1.1"]
    )
    assert await is_ip_allowed("127.0.0.1", blacklist_config)
    assert not await is_ip_allowed("192.168.1.1", blacklist_config)


async def test_is_user_agent_allowed(security_config: SecurityConfig) -> None:
    assert await is_user_agent_allowed("goodbot", security_config)
    assert not await is_user_agent_allowed("badbot", security_config)


async def test_detect_penetration_attempt() -> None:
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={},
        body_content=b"",
    )
    result, _ = await detect_penetration_attempt(request)
    assert not result


async def test_detect_penetration_attempt_xss() -> None:
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"param": "<script>alert('xss')</script>"},
        body_content=b"",
    )
    result, trigger = await detect_penetration_attempt(request)
    assert result
    assert "script" in trigger.lower()


async def test_detect_penetration_attempt_sql_injection() -> None:
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"query": "UNION SELECT NULL--"},
        body_content=b"",
    )
    result, _ = await detect_penetration_attempt(request)
    assert result


async def test_detect_penetration_attempt_directory_traversal() -> None:
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(
        path="/../../etc/passwd",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={},
        body_content=b"",
    )
    result, _ = await detect_penetration_attempt(request)
    assert result


async def test_detect_penetration_attempt_command_injection() -> None:
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"cmd": "|cat /etc/passwd"},
        body_content=b"",
    )
    result, _ = await detect_penetration_attempt(request)
    assert result


async def test_detect_penetration_attempt_path_manipulation() -> None:
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(
        path="/../../../../etc/passwd",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={},
        body_content=b"",
    )
    result, _ = await detect_penetration_attempt(request)
    assert result


async def test_get_ip_country(mocker: MockerFixture) -> None:
    mock_ipinfo = mocker.patch("guard_core.handlers.ipinfo_handler.IPInfoManager")
    mock_db = mock_ipinfo.return_value
    mock_db.get_country.return_value = "US"
    mock_db.reader = True

    config = SecurityConfig(ipinfo_token=IPINFO_TOKEN, blocked_countries=["CN"])

    country = await check_ip_country("1.1.1.1", config, mock_db)
    assert not country

    mock_db.get_country.return_value = "CN"
    country = await check_ip_country("1.1.1.1", config, mock_db)
    assert country


async def test_is_ip_allowed_cloud_providers(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    from guard_core.handlers.cloud_handler import cloud_handler

    mocker.patch("guard_core.utils.check_ip_country", return_value=True)
    mocker.patch.object(
        cloud_handler,
        "is_cloud_ip",
        side_effect=lambda ip, *_: ip.startswith("13."),
    )

    config = SecurityConfig(block_cloud_providers={"AWS"})

    assert await is_ip_allowed("127.0.0.1", config)
    assert not await is_ip_allowed("13.59.255.255", config)
    assert await is_ip_allowed("8.8.8.8", config)


async def test_whitelisted_country(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    mock_ipinfo = mocker.Mock()
    mock_ipinfo.get_country.return_value = "US"
    mock_ipinfo.reader = True

    security_config.whitelist_countries = ["US"]

    assert not await check_ip_country("8.8.8.8", security_config, mock_ipinfo)


async def test_cloud_provider_blocking(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    mocker.patch(
        "guard_core.handlers.cloud_handler.cloud_handler.is_cloud_ip", return_value=True
    )
    security_config.block_cloud_providers = {"AWS"}

    assert not await is_ip_allowed("8.8.8.8", security_config)


async def test_check_ip_country_not_initialized() -> None:
    mock_ipinfo = Mock()
    mock_ipinfo.is_initialized = False
    mock_ipinfo.initialize = AsyncMock()
    mock_ipinfo.get_country.return_value = "US"

    config = SecurityConfig(
        blocked_countries=["CN"],
        geo_ip_handler=mock_ipinfo,
    )

    result = await check_ip_country("1.1.1.1", config, mock_ipinfo)
    assert not result
    mock_ipinfo.initialize.assert_called_once()


async def test_check_ip_country_no_country_found(
    security_config: SecurityConfig,
) -> None:
    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.get_country.return_value = None

    result = await check_ip_country("1.1.1.1", security_config, mock_ipinfo)
    assert not result


async def test_check_ip_country_no_countries_configured(
    caplog: Any,
) -> None:
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, blocked_countries=[], whitelist_countries=[]
    )

    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.get_country.return_value = "US"

    with caplog.at_level(logging.WARNING):
        result = await check_ip_country("1.1.1.1", config, mock_ipinfo)
        assert not result
        assert "No countries blocked or whitelisted" in caplog.text
        assert "1.1.1.1" in caplog.text


async def test_is_ip_allowed_cidr_blacklist() -> None:
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, blacklist=["192.168.1.0/24"], whitelist=[]
    )

    assert not await is_ip_allowed("192.168.1.100", config)
    assert not await is_ip_allowed("192.168.1.1", config)
    assert not await is_ip_allowed("192.168.1.254", config)

    assert await is_ip_allowed("192.168.2.1", config)
    assert await is_ip_allowed("192.168.0.1", config)
    assert await is_ip_allowed("10.0.0.1", config)

    config_multiple = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        blacklist=["192.168.1.0/24", "10.0.0.0/8"],
        whitelist=[],
    )

    assert not await is_ip_allowed("192.168.1.100", config_multiple)
    assert not await is_ip_allowed("10.10.10.10", config_multiple)
    assert await is_ip_allowed("172.16.0.1", config_multiple)


async def test_is_ip_allowed_cidr_whitelist() -> None:
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, whitelist=["192.168.1.0/24"], blacklist=[]
    )

    assert await is_ip_allowed("192.168.1.100", config)
    assert await is_ip_allowed("192.168.1.1", config)
    assert await is_ip_allowed("192.168.1.254", config)

    assert not await is_ip_allowed("192.168.2.1", config)
    assert not await is_ip_allowed("192.168.0.1", config)
    assert not await is_ip_allowed("10.0.0.1", config)

    config_multiple = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        whitelist=["192.168.1.0/24", "10.0.0.0/8"],
        blacklist=[],
    )

    assert await is_ip_allowed("192.168.1.100", config_multiple)
    assert await is_ip_allowed("10.10.10.10", config_multiple)
    assert not await is_ip_allowed("172.16.0.1", config_multiple)


async def test_is_ip_allowed_invalid_ip(caplog: Any) -> None:
    config = SecurityConfig(ipinfo_token="test")

    with caplog.at_level(logging.ERROR):
        result = await is_ip_allowed("invalid-ip", config)
        assert not result


async def test_is_ip_allowed_general_exception(
    caplog: Any, mocker: MockerFixture
) -> None:
    config = SecurityConfig(ipinfo_token="test")

    mock_error = Exception("Unexpected error")
    mocker.patch("guard_core.utils.ip_address", side_effect=mock_error)

    with caplog.at_level(logging.ERROR):
        result = await is_ip_allowed("192.168.1.1", config)
        assert result
        assert "Error checking IP 192.168.1.1" in caplog.text
        assert "Unexpected error" in caplog.text


async def test_detect_penetration_attempt_body_error() -> None:
    mock_request = Mock()
    mock_request.client_host = "127.0.0.1"
    mock_request.query_params = {}
    mock_request.url_path = "/"
    mock_request.headers = {"content-type": "application/json", "content-length": "10"}
    mock_request.body = AsyncMock(side_effect=Exception("Body read error"))

    result, _ = await detect_penetration_attempt(mock_request)
    assert not result


async def test_is_ip_allowed_blocked_country(mocker: MockerFixture) -> None:
    config = SecurityConfig(ipinfo_token="test", blocked_countries=["CN"])

    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.get_country.return_value = "CN"

    mocker.patch("guard_core.utils.check_ip_country", return_value=True)

    result = await is_ip_allowed("192.168.1.1", config, mock_ipinfo)
    assert not result


async def test_detect_penetration_attempt_regex_timeout() -> None:
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"param": "test"},
        body_content=b"",
    )

    async def mock_detect_with_timeout(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "is_threat": False,
            "threat_score": 0.0,
            "threats": [],
            "context": kwargs.get("context", "unknown"),
            "original_length": len(kwargs.get("content", "")),
            "processed_length": len(kwargs.get("content", "")),
            "execution_time": 2.1,
            "detection_method": "enhanced",
            "timeouts": ["test_pattern"],
            "correlation_id": kwargs.get("correlation_id"),
        }

    with (
        patch.object(
            sus_patterns_handler, "detect", side_effect=mock_detect_with_timeout
        ),
        patch("logging.getLogger") as mock_get_logger,
    ):
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        result, trigger = await detect_penetration_attempt(request)

        assert not result
        assert trigger == ""


async def test_detect_penetration_attempt_regex_exception() -> None:
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"param": "test"},
        body_content=b"",
    )

    async def mock_detect_with_exception(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise Exception("Unexpected detection error")

    with (
        patch.object(
            sus_patterns_handler, "detect", side_effect=mock_detect_with_exception
        ),
        patch("logging.error") as mock_error,
    ):
        result, trigger = await detect_penetration_attempt(request)

        assert not result
        assert trigger == ""

        mock_error.assert_called()
        error_msg = mock_error.call_args[0][0]
        assert "Enhanced detection failed" in error_msg


async def test_detect_penetration_json_non_regex_threat() -> None:
    from tests.conftest import MockGuardRequest

    json_payload = '{"username": "admin", "password": "test_password"}'

    request = MockGuardRequest(
        path="/api/login",
        method="POST",
        headers={},
        client_host="127.0.0.1",
        query_params={"data": json_payload},
        body_content=b"",
    )

    async def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
        content = args[0] if args else kwargs.get("content", "")
        if "test_password" in content:
            return {
                "is_threat": True,
                "threats": [{"type": "semantic", "attack_type": "credential_stuffing"}],
            }
        return {"is_threat": False, "threats": []}

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        result, trigger = await detect_penetration_attempt(request)

        assert result is True
        assert "JSON field 'password' contains: semantic" in trigger


async def test_detect_penetration_semantic_threat() -> None:
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"search": "SELECT * FROM users WHERE admin=1"},
        body_content=b"",
    )

    async def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "is_threat": True,
            "threats": [
                {
                    "type": "semantic",
                    "attack_type": "sql_injection",
                    "probability": 0.95,
                }
            ],
        }

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        result, trigger = await detect_penetration_attempt(request)

        assert result is True
        assert "Semantic attack: sql_injection (score: 0.95)" in trigger


async def test_detect_penetration_semantic_threat_with_score() -> None:
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"input": "malicious_content"},
        body_content=b"",
    )

    async def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "is_threat": True,
            "threats": [
                {"type": "semantic", "attack_type": "suspicious", "threat_score": 0.88}
            ],
        }

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        result, trigger = await detect_penetration_attempt(request)

        assert result is True
        assert "Semantic attack: suspicious (score: 0.88)" in trigger


async def test_detect_penetration_fallback_pattern_match() -> None:
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"test": "<script>alert(1)</script>"},
        body_content=b"",
    )

    async def mock_detect_error(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("Detection engine failure")

    mock_pattern = MagicMock()
    mock_pattern.search.return_value = MagicMock()

    _all_ctx = frozenset(
        {"query_param", "header", "url_path", "request_body", "unknown"}
    )
    with (
        patch.object(sus_patterns_handler, "detect", side_effect=mock_detect_error),
        patch.object(
            sus_patterns_handler,
            "get_all_compiled_patterns",
            return_value=[(mock_pattern, _all_ctx)],
        ),
        patch("logging.error") as mock_error,
    ):
        result, trigger = await detect_penetration_attempt(request)

        assert result is True
        assert "Value matched pattern (fallback)" in trigger

        mock_error.assert_called()
        error_msg = mock_error.call_args[0][0]
        assert "Enhanced detection failed" in error_msg


async def test_detect_penetration_fallback_pattern_exception() -> None:
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"test": "normal_content"},
        body_content=b"",
    )

    async def mock_detect_error(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("Detection engine failure")

    mock_pattern = MagicMock()
    mock_pattern.search.side_effect = Exception("Pattern error")

    _all_ctx = frozenset(
        {"query_param", "header", "url_path", "request_body", "unknown"}
    )
    with (
        patch.object(sus_patterns_handler, "detect", side_effect=mock_detect_error),
        patch.object(
            sus_patterns_handler,
            "get_all_compiled_patterns",
            return_value=[(mock_pattern, _all_ctx)],
        ),
        patch("logging.error") as mock_log_error,
    ):
        result, trigger = await detect_penetration_attempt(request)

        assert result is False
        assert trigger == ""

        assert mock_log_error.call_count >= 1
        for call in mock_log_error.call_args_list:
            assert "Enhanced detection failed" in call[0][0]
            assert "Detection engine failure" in call[0][0]


async def test_detect_penetration_short_body() -> None:
    from tests.conftest import MockGuardRequest

    short_body = b"<script>XSS</script>"

    request = MockGuardRequest(
        path="/submit",
        method="POST",
        headers={},
        client_host="127.0.0.1",
        query_params={},
        body_content=short_body,
    )

    with patch("logging.warning") as mock_warning:
        result, trigger = await detect_penetration_attempt(request)

        assert result is True
        assert "Request body:" in trigger

        warning_calls = mock_warning.call_args_list
        body_logged = False
        for call in warning_calls:
            if "<script>XSS</script>" in str(call):
                body_logged = True
                break
        assert body_logged


async def test_detect_penetration_empty_threat_fallback() -> None:
    from tests.conftest import MockGuardRequest

    json_payload = '{"field": "suspicious_value"}'

    request = MockGuardRequest(
        path="/api/data",
        method="POST",
        headers={},
        client_host="127.0.0.1",
        query_params={"data": json_payload},
        body_content=b"",
    )

    async def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "is_threat": True,
            "threats": [],
        }

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        result, trigger = await detect_penetration_attempt(request)

        assert result is True
        assert "JSON field 'field' contains threat" in trigger


async def test_detect_penetration_unknown_threat_type() -> None:
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"param": "test_value"},
        body_content=b"",
    )

    async def mock_detect(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {
            "is_threat": True,
            "threats": [{"type": "unknown_type", "data": "some_data"}],
        }

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        result, trigger = await detect_penetration_attempt(request)

        assert result is True
        assert trigger == "Query param 'param': Threat detected"


async def test_is_trusted_proxy_cidr_miss_then_exact_match() -> None:
    from guard_core.utils import _is_trusted_proxy

    assert _is_trusted_proxy("5.5.5.5", ["10.0.0.0/8", "5.5.5.5"]) is True


async def test_extract_request_context_without_client_host() -> None:
    from guard_core.utils import _extract_request_context

    request = MockGuardRequest(client_host=None)
    context = _extract_request_context(request)
    assert context["client_ip"] == "unknown"


async def test_log_activity_suspicious_without_trigger_info() -> None:
    import logging as _logging

    from guard_core.utils import log_activity

    logger = _logging.getLogger("test_log_activity")
    request = MockGuardRequest()
    await log_activity(
        request,
        logger,
        log_type="suspicious",
        reason="test",
        passive_mode=True,
        trigger_info="",
        level="WARNING",
    )


async def test_check_blocked_countries_not_blocked() -> None:
    from guard_core.utils import _check_blocked_countries

    config = MagicMock()
    config.blocked_countries = ["CN"]
    geo = MagicMock()

    async def fake_check(*_args: Any, **_kwargs: Any) -> bool:
        return False

    with patch("guard_core.utils.check_ip_country", side_effect=fake_check):
        allowed = await _check_blocked_countries("1.2.3.4", config, geo)
    assert allowed is True


async def test_detect_penetration_attempt_without_client_host() -> None:
    from guard_core.utils import detect_penetration_attempt

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host=None,
        query_params={},
        body_content=b"",
    )
    detected, trigger = await detect_penetration_attempt(request)
    assert detected is False
    assert trigger == ""


async def test_detect_penetration_skips_non_string_body_values() -> None:
    import json as _json

    from guard_core.utils import detect_penetration_attempt

    body = _json.dumps({"count": 42, "flag": True, "name": "safe"})
    request = MockGuardRequest(
        path="/",
        method="POST",
        headers={"content-type": "application/json"},
        client_host="127.0.0.1",
        body_content=body.encode(),
    )
    detected, trigger = await detect_penetration_attempt(request)
    assert detected is False
    assert trigger == ""


async def test_detect_penetration_skips_excluded_headers() -> None:
    from guard_core.utils import detect_penetration_attempt

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={
            "host": "example.com",
            "user-agent": "test",
            "accept": "*/*",
            "accept-encoding": "gzip",
            "accept-language": "en",
            "cookie": "session=abc",
            "authorization": "Bearer x",
            "content-type": "application/json",
            "content-length": "0",
            "connection": "close",
        },
        client_host="127.0.0.1",
        query_params={},
        body_content=b"",
    )
    detected, trigger = await detect_penetration_attempt(request)
    assert detected is False
    assert trigger == ""
