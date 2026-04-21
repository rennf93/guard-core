import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


class _RaisingConnCtx:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    async def __aenter__(self) -> None:
        raise self._exc

    async def __aexit__(self, *_: object) -> None:
        return None


async def test_ipban_initialize_redis() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    redis = MagicMock()
    await mgr.initialize_redis(redis)
    assert mgr.redis_handler is redis


async def test_ipban_is_banned_redis_expired() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    redis = MagicMock()
    redis.get_key = AsyncMock(return_value=str(time.time() - 100))
    redis.delete = AsyncMock()
    mgr.redis_handler = redis
    result = await mgr.is_ip_banned("1.2.3.4")
    assert result is False
    redis.delete.assert_called_once()


async def test_ipban_is_banned_redis_valid() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    redis = MagicMock()
    redis.get_key = AsyncMock(return_value=str(time.time() + 1000))
    mgr.redis_handler = redis
    result = await mgr.is_ip_banned("5.5.5.5")
    assert result is True


async def test_ipban_is_banned_no_redis_unknown_ip() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.redis_handler = None
    assert await mgr.is_ip_banned("9.9.9.9") is False


async def test_ipban_is_banned_redis_missing_entry() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    redis = MagicMock()
    redis.get_key = AsyncMock(return_value=None)
    mgr.redis_handler = redis
    assert await mgr.is_ip_banned("9.9.9.9") is False


async def test_ipban_singleton_returns_same_instance() -> None:
    IPBanManager._instance = None
    first = IPBanManager()
    second = IPBanManager()
    assert first is second


async def test_ipban_reset_without_redis() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.1.1.1"] = time.time() + 100
    mgr.redis_handler = None
    await mgr.reset()
    assert len(mgr.banned_ips) == 0


async def test_ipban_reset_with_redis() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    config_mock = MagicMock()
    config_mock.redis_prefix = "test:"

    mock_conn = MagicMock()
    mock_conn.keys = AsyncMock(return_value=["test:banned_ips:1.2.3.4"])
    mock_conn.delete = AsyncMock()

    @asynccontextmanager
    async def mock_get_connection() -> AsyncIterator[Any]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = config_mock
    mgr.redis_handler = redis
    await mgr.reset()
    mock_conn.delete.assert_called_once()


async def test_ipban_reset_with_redis_no_keys() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    config_mock = MagicMock()
    config_mock.redis_prefix = "test:"

    mock_conn = MagicMock()
    mock_conn.keys = AsyncMock(return_value=[])
    mock_conn.delete = AsyncMock()

    @asynccontextmanager
    async def mock_get_connection() -> AsyncIterator[Any]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = config_mock
    mgr.redis_handler = redis
    await mgr.reset()
    mock_conn.delete.assert_not_called()


async def test_ipban_unban_with_redis() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.2.3.4"] = time.time() + 1000
    redis = MagicMock()
    redis.delete = AsyncMock()
    mgr.redis_handler = redis
    await mgr.unban_ip("1.2.3.4")
    redis.delete.assert_called_once()


async def test_ipban_unban_with_agent() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.2.3.4"] = time.time() + 1000
    agent = MagicMock()
    agent.send_event = AsyncMock()
    mgr.agent_handler = agent
    with patch(
        "guard_core.handlers.ipban_handler.SecurityEvent", create=True
    ) as mock_event:
        mock_event.return_value = MagicMock()
        await mgr.unban_ip("1.2.3.4")
    agent.send_event.assert_called_once()


async def test_ipban_unban_agent_exception() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.2.3.4"] = time.time() + 1000
    agent = MagicMock()
    agent.send_event = AsyncMock(side_effect=Exception("fail"))
    mgr.agent_handler = agent
    with patch("guard_core.handlers.ipban_handler.SecurityEvent", create=True):
        await mgr.unban_ip("1.2.3.4")


async def test_ratelimit_initialize_redis() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)

    mock_conn = MagicMock()
    mock_conn.script_load = AsyncMock(return_value="sha123")

    @asynccontextmanager
    async def mock_get_connection() -> AsyncIterator[Any]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    mgr.redis_handler = redis
    await mgr.initialize_redis(redis)
    assert mgr.rate_limit_script_sha == "sha123"


async def test_ratelimit_initialize_redis_exception() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)

    redis = MagicMock()
    redis.get_connection = lambda: _RaisingConnCtx(Exception("conn fail"))
    mgr.redis_handler = redis
    await mgr.initialize_redis(redis)
    assert mgr.rate_limit_script_sha is None


async def test_ratelimit_initialize_redis_disabled() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    await mgr.initialize_redis(MagicMock())
    assert mgr.rate_limit_script_sha is None


async def test_ratelimit_redis_count_with_script() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "sha123"

    mock_conn = MagicMock()
    mock_conn.evalsha = AsyncMock(return_value=5)

    @asynccontextmanager
    async def mock_get_connection() -> AsyncIterator[Any]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    count = await mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)
    assert count == 5


async def test_ratelimit_redis_count_without_script() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = None

    mock_pipeline = MagicMock()
    mock_pipeline.zadd = MagicMock()
    mock_pipeline.zremrangebyscore = MagicMock()
    mock_pipeline.zcard = MagicMock()
    mock_pipeline.expire = MagicMock()
    mock_pipeline.execute = AsyncMock(return_value=[1, 0, 3, True])

    mock_conn = MagicMock()
    mock_conn.pipeline = MagicMock(return_value=mock_pipeline)

    @asynccontextmanager
    async def mock_get_connection() -> AsyncIterator[Any]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    count = await mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)
    assert count == 3


async def test_ratelimit_redis_count_redis_error() -> None:
    from redis.exceptions import RedisError

    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "sha123"

    redis = MagicMock()
    redis.get_connection = lambda: _RaisingConnCtx(RedisError("conn fail"))
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    count = await mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)
    assert count is None


async def test_ratelimit_redis_count_generic_error() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "sha123"

    redis = MagicMock()
    redis.get_connection = lambda: _RaisingConnCtx(Exception("generic fail"))
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    count = await mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)
    assert count is None


async def test_ratelimit_in_memory_with_endpoint() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    current = time.time()
    count = mgr._get_in_memory_request_count("1.2.3.4", current - 60, current, "/api")
    assert count == 0


async def test_ratelimit_check_disabled() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=False, enable_rate_limiting=False)
    mgr = RateLimitManager(config)
    req = MockGuardRequest()
    result = await mgr.check_rate_limit(req, "1.2.3.4", AsyncMock())
    assert result is None


async def test_ratelimit_check_falls_back_when_redis_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(
        enable_redis=True, redis_url="redis://localhost:6379", rate_limit=100
    )
    mgr = RateLimitManager(config)
    mgr.redis_handler = MagicMock()
    monkeypatch.setattr(mgr, "_get_redis_request_count", AsyncMock(return_value=None))

    req = MockGuardRequest()
    result = await mgr.check_rate_limit(req, "1.2.3.4", AsyncMock())
    assert result is None


async def test_ratelimit_check_redis_exceeded() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(
        enable_redis=True, redis_url="redis://localhost:6379", rate_limit=5
    )
    mgr = RateLimitManager(config)

    mock_conn = MagicMock()
    mock_conn.evalsha = AsyncMock(return_value=10)

    @asynccontextmanager
    async def mock_get_connection() -> AsyncIterator[Any]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis
    mgr.rate_limit_script_sha = "sha123"

    from tests.conftest import MockGuardResponse

    req = MockGuardRequest()
    create_error = AsyncMock(return_value=MockGuardResponse("rate limited", 429))

    with patch(
        "guard_core.handlers.ratelimit_handler.log_activity", new_callable=AsyncMock
    ):
        result = await mgr.check_rate_limit(req, "1.2.3.4", create_error)
    assert result is not None
    assert result.status_code == 429


async def test_ratelimit_check_redis_ok() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(
        enable_redis=True, redis_url="redis://localhost:6379", rate_limit=100
    )
    mgr = RateLimitManager(config)

    mock_conn = MagicMock()
    mock_conn.evalsha = AsyncMock(return_value=2)

    @asynccontextmanager
    async def mock_get_connection() -> AsyncIterator[Any]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis
    mgr.rate_limit_script_sha = "sha123"

    req = MockGuardRequest()
    result = await mgr.check_rate_limit(req, "1.2.3.4", AsyncMock())
    assert result is None


async def test_ratelimit_reset_redis() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    redis = MagicMock()
    redis.keys = AsyncMock(return_value=["key1"])
    redis.delete_pattern = AsyncMock()
    mgr.redis_handler = redis
    await mgr.reset()
    assert redis.delete_pattern.call_count == 2
    patterns = {call.args[0] for call in redis.delete_pattern.call_args_list}
    assert patterns == {"rate_limit:rate:*", "threat_signal:*"}


async def test_ratelimit_reset_redis_exception() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    redis = MagicMock()
    redis.keys = AsyncMock(side_effect=Exception("fail"))
    mgr.redis_handler = redis
    await mgr.reset()


async def test_ratelimit_reset_redis_no_keys() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    redis = MagicMock()
    redis.keys = AsyncMock(return_value=[])
    redis.delete_pattern = AsyncMock()
    mgr.redis_handler = redis
    await mgr.reset()
    redis.delete_pattern.assert_not_called()


async def test_ratelimit_reset_no_redis() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    mgr.redis_handler = None
    await mgr.reset()


async def test_ratelimit_send_event() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    agent = MagicMock()
    agent.send_event = AsyncMock()
    mgr.agent_handler = agent
    req = MockGuardRequest()
    with patch(
        "guard_core.handlers.ratelimit_handler.SecurityEvent", create=True
    ) as mock_event:
        mock_event.return_value = MagicMock()
        await mgr._send_rate_limit_event(req, "1.2.3.4", 10)
    agent.send_event.assert_called_once()


async def test_ratelimit_send_event_exception() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    agent = MagicMock()
    agent.send_event = AsyncMock(side_effect=Exception("fail"))
    mgr.agent_handler = agent
    req = MockGuardRequest()
    with patch("guard_core.handlers.ratelimit_handler.SecurityEvent", create=True):
        await mgr._send_rate_limit_event(req, "1.2.3.4", 10)


async def test_ratelimit_redis_count_with_endpoint() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "sha123"

    mock_conn = MagicMock()
    mock_conn.evalsha = AsyncMock(return_value=2)

    @asynccontextmanager
    async def mock_get_connection() -> AsyncIterator[Any]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    count = await mgr._get_redis_request_count(
        "1.2.3.4", time.time(), time.time() - 60, endpoint_path="/api"
    )
    assert count == 2


async def test_security_headers_cors_wildcard_credentials() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr._configure_cors(
        cors_origins=["*"],
        cors_allow_credentials=True,
        cors_allow_methods=None,
        cors_allow_headers=None,
    )
    assert mgr.cors_config is not None
    assert mgr.cors_config["allow_credentials"] is False


async def test_security_headers_update_content_type_options() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr._update_default_headers(
        frame_options=None,
        content_type_options="nosniff",
        xss_protection=None,
        referrer_policy=None,
        permissions_policy="UNSET",
    )
    assert mgr.default_headers["X-Content-Type-Options"] == "nosniff"


async def test_security_headers_update_xss_protection() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr._update_default_headers(
        frame_options=None,
        content_type_options=None,
        xss_protection="0",
        referrer_policy=None,
        permissions_policy="UNSET",
    )
    assert mgr.default_headers["X-XSS-Protection"] == "0"


async def test_security_headers_permissions_policy_set() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr._update_default_headers(
        frame_options=None,
        content_type_options=None,
        xss_protection=None,
        referrer_policy=None,
        permissions_policy="camera=()",
    )
    assert mgr.default_headers["Permissions-Policy"] == "camera=()"


async def test_security_headers_permissions_policy_remove() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.default_headers["Permissions-Policy"] = "geolocation=()"
    mgr._update_default_headers(
        frame_options=None,
        content_type_options=None,
        xss_protection=None,
        referrer_policy=None,
        permissions_policy=None,
    )
    assert "Permissions-Policy" not in mgr.default_headers


async def test_security_headers_get_headers_with_agent() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.headers_cache.clear()
    agent = MagicMock()
    agent.send_event = AsyncMock()
    mgr.agent_handler = agent
    with patch.object(
        mgr, "_send_headers_applied_event", new_callable=AsyncMock
    ) as mock_send:
        headers = await mgr.get_headers("/test")
    mock_send.assert_called_once()
    assert isinstance(headers, dict)


async def test_security_headers_wildcard_with_credentials_cors() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": ["*"],
        "allow_credentials": True,
        "allow_methods": ["GET"],
        "allow_headers": ["*"],
    }
    result = await mgr.get_cors_headers("https://example.com")
    assert result == {}


async def test_security_headers_cors_invalid_methods_type() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": ["https://example.com"],
        "allow_credentials": False,
        "allow_methods": "GET",
        "allow_headers": ["*"],
    }
    result = await mgr.get_cors_headers("https://example.com")
    assert "Access-Control-Allow-Methods" in result


async def test_security_headers_cors_invalid_headers_type() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": ["https://example.com"],
        "allow_credentials": False,
        "allow_methods": ["GET"],
        "allow_headers": "*",
    }
    result = await mgr.get_cors_headers("https://example.com")
    assert "Access-Control-Allow-Headers" in result


async def test_security_headers_cors_non_list_origins() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": "not a list",
        "allow_credentials": False,
    }
    result = await mgr.get_cors_headers("https://example.com")
    assert result == {}


async def test_security_headers_cors_origin_not_allowed() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": ["https://allowed.com"],
        "allow_credentials": False,
        "allow_methods": ["GET"],
        "allow_headers": ["*"],
    }
    result = await mgr.get_cors_headers("https://evil.com")
    assert result == {}


async def test_cloud_handler_get_details_invalid_ip() -> None:
    from guard_core.handlers.cloud_handler import CloudManager

    handler = CloudManager()
    result = handler.get_cloud_provider_details("not_valid_ip")
    assert result is None


async def test_redis_handler_keys_disabled() -> None:
    from guard_core.handlers.redis_handler import RedisManager

    config = SecurityConfig(enable_redis=False)
    mgr = RedisManager(config)
    result = await mgr.keys("test*")
    assert result is None


async def test_redis_handler_delete_pattern_disabled() -> None:
    from guard_core.handlers.redis_handler import RedisManager

    config = SecurityConfig(enable_redis=False)
    mgr = RedisManager(config)
    result = await mgr.delete_pattern("test*")
    assert result is None


async def test_redis_handler_keys_with_redis() -> None:
    from guard_core.handlers.redis_handler import RedisManager

    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RedisManager(config)
    await mgr.initialize()
    result = await mgr.keys("nonexistent_pattern_xyz*")
    assert result is not None
    assert isinstance(result, list)
    await mgr.close()


async def test_redis_handler_delete_pattern_with_redis() -> None:
    from guard_core.handlers.redis_handler import RedisManager

    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RedisManager(config)
    await mgr.initialize()
    result = await mgr.delete_pattern("nonexistent_pattern_xyz*")
    assert result is not None
    await mgr.close()


async def test_ratelimit_handle_exceeded_with_agent() -> None:
    RateLimitManager._instance = None
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    agent = MagicMock()
    agent.send_event = AsyncMock()
    mgr.agent_handler = agent
    req = MockGuardRequest()

    from tests.conftest import MockGuardResponse

    create_error = AsyncMock(return_value=MockGuardResponse("rate limited", 429))
    with patch(
        "guard_core.handlers.ratelimit_handler.log_activity", new_callable=AsyncMock
    ):
        with patch("guard_core.handlers.ratelimit_handler.SecurityEvent", create=True):
            result = await mgr._handle_rate_limit_exceeded(
                req, "1.2.3.4", 10, create_error
            )
    assert result.status_code == 429


async def test_responses_factory_cors_disabled() -> None:
    from guard_core.core.events.metrics import MetricsCollector
    from guard_core.core.responses.context import ResponseContext
    from guard_core.core.responses.factory import ErrorResponseFactory
    from tests.conftest import MockGuardResponseFactory

    config = SecurityConfig(enable_redis=False, security_headers={"enabled": False})
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = AsyncMock()
    ctx = ResponseContext(
        config=config,
        logger=MagicMock(),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    factory = ErrorResponseFactory(ctx)
    from tests.conftest import MockGuardResponse

    resp = MockGuardResponse("ok", 200)
    result = await factory.apply_cors_headers(resp, "https://example.com")
    assert result is resp


class TestThreatSignalRateLimiting:
    def _manager(self, **config_kwargs: object) -> RateLimitManager:
        RateLimitManager._instance = None
        config = SecurityConfig(enable_redis=False, **config_kwargs)
        return RateLimitManager(config)

    async def test_record_threat_signal_stores_in_memory(self) -> None:
        mgr = self._manager()
        await mgr.record_threat_signal("1.2.3.4", 0.9)
        assert len(mgr.threat_signals["1.2.3.4"]) == 1
        expiry, score = mgr.threat_signals["1.2.3.4"][0]
        assert score == pytest.approx(0.9)
        assert expiry > 0

    async def test_get_threat_score_sums_active_signals(self) -> None:
        mgr = self._manager()
        await mgr.record_threat_signal("1.2.3.4", 0.5)
        await mgr.record_threat_signal("1.2.3.4", 0.4)
        total = await mgr.get_threat_score("1.2.3.4")
        assert total == pytest.approx(0.9)

    async def test_get_threat_score_expires(self) -> None:
        mgr = self._manager()
        now = time.time()
        mgr.threat_signals["1.2.3.4"].append((now - 1, 0.9))
        assert await mgr.get_threat_score("1.2.3.4") == 0.0
        assert not mgr.threat_signals["1.2.3.4"]

    async def test_get_threat_score_unknown_ip(self) -> None:
        mgr = self._manager()
        assert await mgr.get_threat_score("unknown") == 0.0

    async def test_check_rate_limit_tightens_when_threat_signal_active(self) -> None:
        from tests.conftest import MockGuardResponse

        mgr = self._manager(
            enable_rate_limiting=True,
            rate_limit=100,
            rate_limit_window=60,
            enable_threat_score_rate_limiting=True,
            rate_limit_multiplier_on_threat=0.1,
        )
        create_error = AsyncMock(return_value=MockGuardResponse("blocked", 429))
        req = MockGuardRequest(path="/api")
        await mgr.record_threat_signal("9.9.9.9", 0.9)

        for _ in range(10):
            await mgr.check_rate_limit(
                req, "9.9.9.9", create_error, endpoint_path="/api"
            )
        result = await mgr.check_rate_limit(
            req, "9.9.9.9", create_error, endpoint_path="/api"
        )
        assert result is not None
        assert result.status_code == 429

    async def test_check_rate_limit_unchanged_without_threat_signal(self) -> None:
        from tests.conftest import MockGuardResponse

        mgr = self._manager(
            enable_rate_limiting=True,
            rate_limit=100,
            rate_limit_window=60,
            enable_threat_score_rate_limiting=True,
            rate_limit_multiplier_on_threat=0.1,
        )
        create_error = AsyncMock(return_value=MockGuardResponse("blocked", 429))
        req = MockGuardRequest(path="/api")

        for _ in range(50):
            result = await mgr.check_rate_limit(
                req, "8.8.8.8", create_error, endpoint_path="/api"
            )
            assert result is None

    async def test_explicit_threat_multiplier_overrides_score(self) -> None:
        from tests.conftest import MockGuardResponse

        mgr = self._manager(
            enable_rate_limiting=True,
            rate_limit=100,
            rate_limit_window=60,
            enable_threat_score_rate_limiting=True,
            rate_limit_multiplier_on_threat=0.01,
        )
        create_error = AsyncMock(return_value=MockGuardResponse("blocked", 429))
        req = MockGuardRequest(path="/api")
        await mgr.record_threat_signal("1.1.1.1", 0.9)

        result = await mgr.check_rate_limit(
            req,
            "1.1.1.1",
            create_error,
            endpoint_path="/api",
            threat_multiplier=1.0,
        )
        assert result is None

    async def test_disabling_feature_ignores_signals(self) -> None:
        from tests.conftest import MockGuardResponse

        mgr = self._manager(
            enable_rate_limiting=True,
            rate_limit=100,
            rate_limit_window=60,
            enable_threat_score_rate_limiting=False,
            rate_limit_multiplier_on_threat=0.01,
        )
        create_error = AsyncMock(return_value=MockGuardResponse("blocked", 429))
        req = MockGuardRequest(path="/api")
        await mgr.record_threat_signal("2.2.2.2", 0.9)

        for _ in range(50):
            result = await mgr.check_rate_limit(
                req, "2.2.2.2", create_error, endpoint_path="/api"
            )
            assert result is None

    async def test_reset_clears_threat_signals(self) -> None:
        mgr = self._manager()
        await mgr.record_threat_signal("4.4.4.4", 0.9)
        assert mgr.threat_signals["4.4.4.4"]
        await mgr.reset()
        assert not mgr.threat_signals

    async def test_redis_record_persists_via_sorted_set(self) -> None:
        RateLimitManager._instance = None
        config = SecurityConfig(enable_redis=True, redis_url="redis://x")
        mgr = RateLimitManager(config)
        mock_conn = MagicMock()
        mock_conn.zadd = AsyncMock()
        mock_conn.expire = AsyncMock()

        @asynccontextmanager
        async def conn_ctx() -> AsyncIterator[Any]:
            yield mock_conn

        redis = MagicMock()
        redis.config.redis_prefix = "gc:"
        redis.get_connection = conn_ctx
        mgr.redis_handler = redis

        await mgr.record_threat_signal("5.5.5.5", 0.7)
        mock_conn.zadd.assert_awaited_once()
        mock_conn.expire.assert_awaited_once()

    async def test_redis_get_threat_score_sums_members(self) -> None:
        RateLimitManager._instance = None
        config = SecurityConfig(enable_redis=True, redis_url="redis://x")
        mgr = RateLimitManager(config)
        mock_conn = MagicMock()
        mock_conn.zremrangebyscore = AsyncMock()
        mock_conn.zrange = AsyncMock(return_value=[b"1000:0.7", "2000:0.3"])

        @asynccontextmanager
        async def conn_ctx() -> AsyncIterator[Any]:
            yield mock_conn

        redis = MagicMock()
        redis.config.redis_prefix = "gc:"
        redis.get_connection = conn_ctx
        mgr.redis_handler = redis

        total = await mgr.get_threat_score("6.6.6.6")
        assert total == pytest.approx(1.0)

    async def test_redis_error_on_record_falls_back_to_in_memory(self) -> None:
        from redis.exceptions import RedisError

        RateLimitManager._instance = None
        config = SecurityConfig(enable_redis=True, redis_url="redis://x")
        mgr = RateLimitManager(config)
        redis = MagicMock()
        redis.config.redis_prefix = "gc:"
        redis.get_connection = lambda: _RaisingConnCtx(RedisError("boom"))
        mgr.redis_handler = redis

        await mgr.record_threat_signal("7.7.7.7", 0.8)
        assert mgr.threat_signals["7.7.7.7"]

    async def test_redis_error_on_query_returns_none(self) -> None:
        from redis.exceptions import RedisError

        RateLimitManager._instance = None
        config = SecurityConfig(enable_redis=True, redis_url="redis://x")
        mgr = RateLimitManager(config)
        redis = MagicMock()
        redis.config.redis_prefix = "gc:"
        redis.get_connection = lambda: _RaisingConnCtx(RedisError("boom"))
        mgr.redis_handler = redis

        redis_score = await mgr._get_threat_score_redis("7.7.7.7", time.time())
        assert redis_score is None

    async def test_get_threat_score_falls_back_to_memory_on_redis_error(
        self,
    ) -> None:
        from redis.exceptions import RedisError

        RateLimitManager._instance = None
        config = SecurityConfig(enable_redis=True, redis_url="redis://x")
        mgr = RateLimitManager(config)
        redis = MagicMock()
        redis.config.redis_prefix = "gc:"
        redis.get_connection = lambda: _RaisingConnCtx(RedisError("boom"))
        mgr.redis_handler = redis

        mgr.threat_signals["8.8.8.8"].append((time.time() + 100, 0.6))
        total = await mgr.get_threat_score("8.8.8.8")
        assert total == pytest.approx(0.6)

    async def test_redis_get_threat_score_ignores_malformed_member(self) -> None:
        RateLimitManager._instance = None
        config = SecurityConfig(enable_redis=True, redis_url="redis://x")
        mgr = RateLimitManager(config)
        mock_conn = MagicMock()
        mock_conn.zremrangebyscore = AsyncMock()
        mock_conn.zrange = AsyncMock(return_value=[b"malformed_no_colon", b"1000:0.5"])

        @asynccontextmanager
        async def conn_ctx() -> AsyncIterator[Any]:
            yield mock_conn

        redis = MagicMock()
        redis.config.redis_prefix = "gc:"
        redis.get_connection = conn_ctx
        mgr.redis_handler = redis

        total = await mgr.get_threat_score("9.9.9.9")
        assert total == pytest.approx(0.5)
