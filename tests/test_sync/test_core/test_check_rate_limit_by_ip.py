import logging
import time
from unittest.mock import MagicMock

from redis.exceptions import NoScriptError, RedisError

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ratelimit_handler import (
    RateLimitManager,
    _redis_request_count,
    check_rate_limit_by_ip,
)
from guard_core.sync.handlers.redis_handler import redis_handler


class _FailingConnection:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def __enter__(self) -> None:
        raise self._exc

    def __exit__(self, *_args: object) -> None:
        return None


def _broken_redis_handler() -> MagicMock:
    redis = MagicMock()
    redis.config = MagicMock(redis_prefix="test:")
    redis.get_connection = lambda: _FailingConnection(RedisError("down"))
    return redis


def test_under_limit_stays_allowed() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=2, rate_limit_window=60)

    assert check_rate_limit_by_ip("203.0.113.1", config) is True
    assert check_rate_limit_by_ip("203.0.113.1", config) is True


def test_over_limit_becomes_blocked() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=1, rate_limit_window=60)

    assert check_rate_limit_by_ip("203.0.113.2", config) is True
    assert check_rate_limit_by_ip("203.0.113.2", config) is False


def test_window_expiry_recovers_after_block() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=1, rate_limit_window=1)

    assert check_rate_limit_by_ip("203.0.113.3", config) is True
    assert check_rate_limit_by_ip("203.0.113.3", config) is False

    time.sleep(1.1)

    assert check_rate_limit_by_ip("203.0.113.3", config) is True


def test_redis_path_enforces_limit(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.rate_limit = 2
    security_config_redis.rate_limit_window = 60
    handler = redis_handler(security_config_redis)
    handler.initialize()
    try:
        ip = "203.0.113.4"
        assert (
            check_rate_limit_by_ip(
                ip, security_config_redis, redis_handler=handler, endpoint_path="ws"
            )
            is True
        )
        assert (
            check_rate_limit_by_ip(
                ip, security_config_redis, redis_handler=handler, endpoint_path="ws"
            )
            is True
        )
        assert (
            check_rate_limit_by_ip(
                ip, security_config_redis, redis_handler=handler, endpoint_path="ws"
            )
            is False
        )
    finally:
        handler.close()


def test_falls_back_to_in_memory_when_redis_handler_not_supplied() -> None:
    config = SecurityConfig(enable_redis=True, rate_limit=1, rate_limit_window=60)

    ip = "203.0.113.5"
    assert check_rate_limit_by_ip(ip, config) is True
    assert check_rate_limit_by_ip(ip, config) is False


def test_redis_error_falls_back_to_in_memory_count() -> None:
    config = SecurityConfig(enable_redis=True, rate_limit=1, rate_limit_window=60)
    redis = _broken_redis_handler()

    ip = "203.0.113.6"
    assert check_rate_limit_by_ip(ip, config, redis_handler=redis) is True
    assert check_rate_limit_by_ip(ip, config, redis_handler=redis) is False


def test_no_singleton_mutation_regression() -> None:
    config_a = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)
    pipeline_manager = RateLimitManager(config_a)

    config_b = SecurityConfig(enable_redis=False, rate_limit=1, rate_limit_window=60)
    check_rate_limit_by_ip("203.0.113.7", config_b)

    assert RateLimitManager._instance is pipeline_manager
    assert pipeline_manager.config is config_a


def test_endpoint_path_namespacing_isolates_budgets() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=1, rate_limit_window=60)
    ip = "203.0.113.8"

    assert check_rate_limit_by_ip(ip, config, endpoint_path="a") is True
    assert check_rate_limit_by_ip(ip, config, endpoint_path="a") is False
    assert check_rate_limit_by_ip(ip, config, endpoint_path="b") is True


def test_default_endpoint_path_shares_pipeline_bucket_bidirectionally(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.rate_limit = 3
    security_config_redis.rate_limit_window = 60
    handler = redis_handler(security_config_redis)
    handler.initialize()
    try:
        ip = "203.0.113.9"
        RateLimitManager._instance = None
        pipeline = RateLimitManager(security_config_redis)
        pipeline.redis_handler = handler

        count = pipeline._get_redis_request_count(ip, time.time(), time.time() - 60)
        assert count == 1

        assert check_rate_limit_by_ip(ip, security_config_redis, handler) is True

        count = pipeline._get_redis_request_count(ip, time.time(), time.time() - 60)
        assert count == 3

        assert check_rate_limit_by_ip(ip, security_config_redis, handler) is False
    finally:
        handler.close()


def test_endpoint_path_ws_is_disjoint_from_pipeline_bucket(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.rate_limit = 2
    security_config_redis.rate_limit_window = 60
    handler = redis_handler(security_config_redis)
    handler.initialize()
    try:
        ip = "203.0.113.12"
        RateLimitManager._instance = None
        pipeline = RateLimitManager(security_config_redis)
        pipeline.redis_handler = handler

        assert pipeline._get_redis_request_count(ip, time.time(), time.time() - 60) == 1
        assert pipeline._get_redis_request_count(ip, time.time(), time.time() - 60) == 2

        assert (
            check_rate_limit_by_ip(
                ip, security_config_redis, handler, endpoint_path="ws"
            )
            is True
        )
        assert (
            check_rate_limit_by_ip(
                ip, security_config_redis, handler, endpoint_path="ws"
            )
            is True
        )
        assert (
            check_rate_limit_by_ip(
                ip, security_config_redis, handler, endpoint_path="ws"
            )
            is False
        )

        count = pipeline._get_redis_request_count(ip, time.time(), time.time() - 60)
        assert count == 3
    finally:
        handler.close()


def test_enable_rate_limiting_false_returns_true() -> None:
    config = SecurityConfig(enable_rate_limiting=False)

    assert check_rate_limit_by_ip("203.0.113.10", config) is True


def test_redis_request_count_reload_without_callback() -> None:
    conn = MagicMock()
    conn.evalsha = MagicMock(side_effect=[NoScriptError("NOSCRIPT"), 1])
    conn.script_load = MagicMock(return_value="newsha")

    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=conn)
    cm.__exit__ = MagicMock(return_value=None)
    redis = MagicMock()
    redis.config = MagicMock(redis_prefix="test:")
    redis.get_connection = MagicMock(return_value=cm)

    count, new_sha = _redis_request_count(
        redis,
        logging.getLogger("test.check_rate_limit_by_ip"),
        "203.0.113.11",
        time.time(),
        time.time() - 60,
        60,
        10,
        "oldsha",
        None,
    )

    assert count == 1
    assert new_sha == "newsha"


def test_unparseable_ip_raises_value_error_ws_collision_string() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)

    try:
        check_rate_limit_by_ip("1.2.3.4:ws", config)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_unparseable_ip_raises_value_error_empty_string() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)

    try:
        check_rate_limit_by_ip("", config)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_unparseable_ip_raises_value_error_garbage_string() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)

    try:
        check_rate_limit_by_ip("not-an-ip", config)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_colon_in_endpoint_path_raises_value_error() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)

    try:
        check_rate_limit_by_ip("203.0.113.20", config, endpoint_path="a:b")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_rejected_ip_records_no_hit_when_rate_limiting_enabled() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=1, rate_limit_window=60)

    try:
        check_rate_limit_by_ip("not-an-ip", config)
    except ValueError:
        pass

    assert check_rate_limit_by_ip("203.0.113.21", config) is True


def test_rejected_ip_records_no_hit_when_rate_limiting_disabled() -> None:
    disabled_config = SecurityConfig(enable_rate_limiting=False)

    try:
        check_rate_limit_by_ip("not-an-ip", disabled_config)
    except ValueError:
        pass

    enabled_config = SecurityConfig(
        enable_redis=False, rate_limit=1, rate_limit_window=60
    )
    assert check_rate_limit_by_ip("203.0.113.22", enabled_config) is True


def test_rejected_endpoint_path_records_no_hit() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=1, rate_limit_window=60)

    try:
        check_rate_limit_by_ip("203.0.113.23", config, endpoint_path="a:b")
    except ValueError:
        pass

    assert check_rate_limit_by_ip("203.0.113.23", config) is True


def test_valid_ipv4_accepted() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)

    assert check_rate_limit_by_ip("203.0.113.24", config) is True


def test_valid_ipv6_literal_accepted() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)

    assert check_rate_limit_by_ip("2001:db8::1", config) is True


def test_ipv6_shares_pipeline_bucket_bidirectionally(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.rate_limit = 3
    security_config_redis.rate_limit_window = 60
    handler = redis_handler(security_config_redis)
    handler.initialize()
    try:
        ip = "2001:db8::99"
        RateLimitManager._instance = None
        pipeline = RateLimitManager(security_config_redis)
        pipeline.redis_handler = handler

        count = pipeline._get_redis_request_count(ip, time.time(), time.time() - 60)
        assert count == 1

        assert check_rate_limit_by_ip(ip, security_config_redis, handler) is True

        count = pipeline._get_redis_request_count(ip, time.time(), time.time() - 60)
        assert count == 3

        assert check_rate_limit_by_ip(ip, security_config_redis, handler) is False
    finally:
        handler.close()


def test_primitive_raises_instead_of_colliding_with_pipeline_bucket(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.rate_limit = 2
    security_config_redis.rate_limit_window = 60
    handler = redis_handler(security_config_redis)
    handler.initialize()
    try:
        RateLimitManager._instance = None
        pipeline = RateLimitManager(security_config_redis)
        pipeline.redis_handler = handler

        count = pipeline._get_redis_request_count(
            "1.2.3.4", time.time(), time.time() - 60, endpoint_path="ws"
        )
        assert count == 1

        try:
            check_rate_limit_by_ip("1.2.3.4:ws", security_config_redis, handler)
            raise AssertionError("expected ValueError")
        except ValueError:
            pass

        count = pipeline._get_redis_request_count(
            "1.2.3.4", time.time(), time.time() - 60, endpoint_path="ws"
        )
        assert count == 2
    finally:
        handler.close()
