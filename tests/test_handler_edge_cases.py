import ipaddress
import time
from collections import deque
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from guard_core.handlers.cloud_handler import CloudManager
from guard_core.handlers.ipban_handler import IPBanManager, reset_global_state
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest, MockGuardResponse, MockGuardResponseFactory


async def test_ipban_in_memory_expired() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.2.3.4"] = time.time() - 100
    result = await mgr.is_ip_banned("1.2.3.4")
    assert result is False


async def test_ipban_in_memory_valid() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.2.3.4"] = time.time() + 1000
    result = await mgr.is_ip_banned("1.2.3.4")
    assert result is True


async def test_ipban_reset_global_state() -> None:
    IPBanManager._instance = None
    await reset_global_state()
    from guard_core.handlers import ipban_handler

    assert ipban_handler.ip_ban_manager is not None


async def test_ratelimit_popleft_stale_timestamps() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    old_time = time.time() - 120
    current = time.time()
    mgr.request_timestamps["1.2.3.4"] = deque([old_time, old_time + 1])
    count = mgr._get_in_memory_request_count("1.2.3.4", current - 60, current)
    assert count == 0


async def test_cloud_handler_get_details_match() -> None:
    handler = CloudManager()
    network = ipaddress.ip_network("10.0.0.0/8")
    handler.ip_ranges = {"AWS": {network}}
    result = handler.get_cloud_provider_details("10.1.2.3", {"AWS"})
    assert result is not None
    assert result[0] == "AWS"


async def test_cloud_handler_get_details_no_match() -> None:
    handler = CloudManager()
    network = ipaddress.ip_network("10.0.0.0/8")
    handler.ip_ranges = {"AWS": {network}}
    result = handler.get_cloud_provider_details("192.168.1.1", {"AWS"})
    assert result is None


async def test_redis_delete_pattern_with_keys() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RedisManager(config)
    await mgr.initialize()
    await mgr.set_key("test_dp", "key1", "value1")
    result = await mgr.delete_pattern("test_dp:*")
    assert result is not None
    await mgr.close()


async def test_security_headers_get_headers_agent_event() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.headers_cache.clear()
    agent = MagicMock()
    agent.send_event = AsyncMock()
    mgr.agent_handler = agent
    with patch(
        "guard_core.handlers.security_headers_handler.SecurityEvent", create=True
    ) as mock_event:
        mock_event.return_value = MagicMock()
        headers = await mgr.get_headers("/api/test")
    assert isinstance(headers, dict)


async def test_security_headers_wildcard_credentials_true() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": ["*"],
        "allow_credentials": True,
        "allow_methods": ["GET"],
        "allow_headers": ["*"],
    }
    result = mgr._is_wildcard_with_credentials(["*"])
    assert result is True


async def test_security_headers_singleton_returns_existing_instance() -> None:
    SecurityHeadersManager._instance = None
    first = SecurityHeadersManager()
    second = SecurityHeadersManager()
    assert first is second


async def test_security_headers_singleton_race_inner_check_false() -> None:
    SecurityHeadersManager._instance = None
    pre_existing = object.__new__(SecurityHeadersManager)

    class _RaceLock:
        def __enter__(self) -> "_RaceLock":
            SecurityHeadersManager._instance = pre_existing
            return self

        def __exit__(self, *_: Any) -> None:
            return None

    lock_attr = "_lock"
    original_lock = SecurityHeadersManager._lock
    setattr(SecurityHeadersManager, lock_attr, _RaceLock())
    try:
        result = SecurityHeadersManager()
    finally:
        setattr(SecurityHeadersManager, lock_attr, original_lock)
        SecurityHeadersManager._instance = None

    assert result is pre_existing


async def test_responses_factory_cors_with_headers() -> None:
    from guard_core.core.events.metrics import MetricsCollector
    from guard_core.core.responses.context import ResponseContext
    from guard_core.core.responses.factory import ErrorResponseFactory

    SecurityHeadersManager._instance = None
    sec_mgr = SecurityHeadersManager()
    sec_mgr._configure_cors(
        cors_origins=["https://example.com"],
        cors_allow_credentials=False,
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
    )

    config = SecurityConfig(
        enable_redis=False,
        security_headers={"enabled": True},
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
    )
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = AsyncMock()
    ctx = ResponseContext(
        config=config,
        logger=MagicMock(),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    factory = ErrorResponseFactory(ctx)
    resp = MockGuardResponse("ok", 200)
    cors_headers = await sec_mgr.get_cors_headers("https://example.com")
    assert "Access-Control-Allow-Origin" in cors_headers
    result = await factory.apply_cors_headers(resp, "https://example.com")
    assert result is not None


async def test_utils_extract_ip_null_client_host() -> None:
    from guard_core.utils import _extract_ip_from_request

    req = MockGuardRequest(client_host=None)
    result = _extract_ip_from_request(req)
    assert result == "unknown"


async def test_utils_log_country_check_no_geolocation() -> None:
    from guard_core.utils import _log_country_check_result

    _log_country_check_result("1.2.3.4", None, "no_geolocation")


async def test_utils_log_country_check_unknown_result_type() -> None:
    from guard_core.utils import _log_country_check_result

    _log_country_check_result("1.2.3.4", "US", "not_a_real_type")


async def test_utils_log_at_level_unknown_level_is_noop() -> None:
    import logging as _logging

    from guard_core.utils import _log_at_level

    logger = _logging.getLogger("test_log_at_level_noop")
    _log_at_level(logger, "UNKNOWN_LEVEL", "msg that should be ignored")


async def test_utils_check_country_no_geolocation() -> None:
    from guard_core.utils import check_ip_country

    config = MagicMock()
    config.blocked_countries = ["CN"]
    config.whitelist_countries = []
    geo = MagicMock()
    geo.is_initialized = True
    geo.get_country = MagicMock(return_value=None)
    result = await check_ip_country(MockGuardRequest(), config, geo)
    assert result is False


async def test_utils_detect_penetration_json_field_threat() -> None:
    from guard_core.utils import detect_penetration_attempt

    req = MockGuardRequest(
        path="/api",
        headers={"content-type": "application/json"},
        body_content=b'{"name": "SELECT * FROM users"}',
        query_params={},
    )
    result, trigger = await detect_penetration_attempt(req)
    assert isinstance(result, bool)


async def test_utils_detect_penetration_header_threat() -> None:
    from guard_core.utils import detect_penetration_attempt

    req = MockGuardRequest(
        path="/api",
        headers={"X-Custom": "<script>alert(1)</script>"},
        query_params={},
    )
    result, trigger = await detect_penetration_attempt(req)
    assert isinstance(result, bool)


async def test_utils_check_json_data_regex_threat() -> None:
    from guard_core.utils import _check_json_fields

    mock_result = {
        "is_threat": True,
        "threats": [{"type": "regex", "pattern": "SELECT.*FROM"}],
    }
    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_handler:
        mock_handler.detect = AsyncMock(return_value=mock_result)
        detected, info = await _check_json_fields(
            {"name": "SELECT * FROM users"}, "body", "1.2.3.4", "corr-1"
        )
    assert detected is True
    assert "matched pattern" in info


async def test_utils_check_json_data_other_threat() -> None:
    from guard_core.utils import _check_json_fields

    mock_result = {
        "is_threat": True,
        "threats": [{"type": "heuristic"}],
    }
    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_handler:
        mock_handler.detect = AsyncMock(return_value=mock_result)
        detected, info = await _check_json_fields(
            {"field": "payload"}, "body", "1.2.3.4", "corr-1"
        )
    assert detected is True
    assert "contains:" in info


async def test_utils_check_json_data_no_threats_list() -> None:
    from guard_core.utils import _check_json_fields

    mock_result = {"is_threat": True, "threats": []}
    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_handler:
        mock_handler.detect = AsyncMock(return_value=mock_result)
        detected, info = await _check_json_fields(
            {"field": "val"}, "body", "1.2.3.4", "corr-1"
        )
    assert detected is True
    assert "contains threat" in info


async def test_utils_check_json_data_clean() -> None:
    from guard_core.utils import _check_json_fields

    mock_result = {"is_threat": False, "threats": []}
    with patch(
        "guard_core.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_handler:
        mock_handler.detect = AsyncMock(return_value=mock_result)
        detected, info = await _check_json_fields(
            {"field": "safe"}, "body", "1.2.3.4", "corr-1"
        )
    assert detected is False


async def test_utils_detect_header_threat() -> None:
    from guard_core.utils import _check_request_component

    with patch(
        "guard_core.utils._check_value_enhanced",
        new_callable=AsyncMock,
        return_value=(True, "XSS detected"),
    ):
        detected, trigger = await _check_request_component(
            "<script>", "header:X-Evil", "header 'X-Evil'", "1.2.3.4", "corr-1"
        )
    assert detected is True


async def test_utils_detect_penetration_header_match() -> None:
    from guard_core.utils import detect_penetration_attempt

    with patch(
        "guard_core.utils._check_request_component", new_callable=AsyncMock
    ) as mock_check:
        call_count = 0

        async def side_effect(
            value: Any,
            context: str,
            component_name: str,
            client_ip: str,
            correlation_id: str,
        ) -> tuple[bool, str]:
            nonlocal call_count
            call_count += 1
            if "header" in context and "X-Evil" in context:
                return True, "XSS detected"
            return False, ""

        mock_check.side_effect = side_effect

        req = MockGuardRequest(
            path="/safe",
            headers={"X-Evil": "<script>alert(1)</script>"},
            query_params={},
        )
        result, trigger = await detect_penetration_attempt(req)
    assert result is True
    assert "Header" in trigger


async def test_security_headers_get_headers_agent_sends_event() -> None:
    from guard_core.handlers.security_headers_handler import security_headers_manager

    security_headers_manager.headers_cache.clear()
    agent = MagicMock()
    agent.send_event = AsyncMock()
    original_agent = security_headers_manager.agent_handler
    security_headers_manager.agent_handler = agent
    try:
        with patch(
            "guard_core.handlers.security_headers_handler.SecurityEvent", create=True
        ) as mock_event_cls:
            mock_event_cls.return_value = MagicMock()
            await security_headers_manager.get_headers("/agent/test/path")
        agent.send_event.assert_called_once()
    finally:
        security_headers_manager.agent_handler = original_agent


async def test_security_headers_get_headers_cache_hit() -> None:
    from guard_core.handlers.security_headers_handler import security_headers_manager

    security_headers_manager.headers_cache.clear()
    first = await security_headers_manager.get_headers("/cache/hit/test")
    assert isinstance(first, dict)
    second = await security_headers_manager.get_headers("/cache/hit/test")
    assert second is first


async def test_security_headers_is_wildcard_with_creds_true() -> None:
    from guard_core.handlers.security_headers_handler import security_headers_manager

    original_cors = security_headers_manager.cors_config
    security_headers_manager.cors_config = {
        "origins": ["*"],
        "allow_credentials": True,
    }
    try:
        result = security_headers_manager._is_wildcard_with_credentials(["*"])
        assert result is True
        cors_result = await security_headers_manager.get_cors_headers(
            "https://test.com"
        )
        assert cors_result == {}
    finally:
        security_headers_manager.cors_config = original_cors


async def test_security_headers_is_wildcard_no_creds() -> None:
    from guard_core.handlers.security_headers_handler import security_headers_manager

    original_cors = security_headers_manager.cors_config
    security_headers_manager.cors_config = {
        "origins": ["*"],
        "allow_credentials": False,
    }
    try:
        result = security_headers_manager._is_wildcard_with_credentials(["*"])
        assert result is False
    finally:
        security_headers_manager.cors_config = original_cors


async def test_security_headers_is_wildcard_no_cors_config() -> None:
    from guard_core.handlers.security_headers_handler import security_headers_manager

    original_cors = security_headers_manager.cors_config
    security_headers_manager.cors_config = None
    try:
        result = security_headers_manager._is_wildcard_with_credentials(["*"])
        assert result is False
    finally:
        security_headers_manager.cors_config = original_cors


async def test_responses_factory_cors_applies_headers() -> None:
    from guard_core.core.events.metrics import MetricsCollector
    from guard_core.core.responses.context import ResponseContext
    from guard_core.core.responses.factory import ErrorResponseFactory

    config = SecurityConfig(
        enable_redis=False,
        security_headers={"enabled": True},
    )
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = AsyncMock()
    ctx = ResponseContext(
        config=config,
        logger=MagicMock(),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    factory = ErrorResponseFactory(ctx)
    with patch(
        "guard_core.core.responses.factory.security_headers_manager"
    ) as mock_shm:
        mock_shm.get_cors_headers = AsyncMock(
            return_value={"Access-Control-Allow-Origin": "*"}
        )
        resp = MockGuardResponse("ok", 200)
        result = await factory.apply_cors_headers(resp, "https://example.com")
    assert "Access-Control-Allow-Origin" in result.headers
