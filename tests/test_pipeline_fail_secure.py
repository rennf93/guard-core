from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig


def _redis_failing_check(config: SecurityConfig) -> MagicMock:
    check = MagicMock()
    check.check_name = "ip_security"
    check.config = config
    check.check = AsyncMock(side_effect=GuardRedisError(503, "Redis connection failed"))
    check.create_error_response = AsyncMock(return_value="BLOCKED")
    return check


def test_default_security_config_is_fail_secure() -> None:
    config = SecurityConfig()
    assert hasattr(config, "fail_secure")
    assert config.fail_secure is True


def test_fail_secure_can_be_disabled() -> None:
    config = SecurityConfig(fail_secure=False)
    assert config.fail_secure is False


@pytest.mark.asyncio
async def test_pipeline_returns_blocked_when_fail_secure_and_check_raises() -> None:
    middleware = MagicMock()
    middleware.config = SecurityConfig(fail_secure=True)
    middleware.logger = MagicMock()

    failing_check = MagicMock()
    failing_check.check_name = "boom"
    failing_check.config = middleware.config
    failing_check.is_muted = False
    failing_check.check = AsyncMock(side_effect=RuntimeError("boom"))
    failing_check.create_error_response = AsyncMock(return_value="BLOCKED")

    pipeline = SecurityCheckPipeline([failing_check])
    result = await pipeline.execute(MagicMock())
    assert result == "BLOCKED"


@pytest.mark.asyncio
async def test_pipeline_falls_through_when_not_fail_secure() -> None:
    middleware = MagicMock()
    middleware.config = SecurityConfig(fail_secure=False)
    middleware.logger = MagicMock()

    failing_check = MagicMock()
    failing_check.check_name = "boom"
    failing_check.config = middleware.config
    failing_check.is_muted = False
    failing_check.check = AsyncMock(side_effect=RuntimeError("boom"))

    pipeline = SecurityCheckPipeline([failing_check])
    result = await pipeline.execute(MagicMock())
    assert result is None


def test_default_security_config_is_not_redis_fail_open() -> None:
    config = SecurityConfig()
    assert config.redis_fail_open is False


@pytest.mark.asyncio
async def test_pipeline_blocks_on_redis_error_with_default_config() -> None:
    """fail_secure is the single source of truth by default: a Redis error
    blocks the request unless redis_fail_open is explicitly opted into."""
    failing_check = _redis_failing_check(SecurityConfig(fail_secure=True))

    pipeline = SecurityCheckPipeline([failing_check])
    result = await pipeline.execute(MagicMock())

    assert result == "BLOCKED"


@pytest.mark.asyncio
async def test_pipeline_fails_open_on_redis_error_despite_fail_secure() -> None:
    failing_check = _redis_failing_check(
        SecurityConfig(fail_secure=True, redis_fail_open=True)
    )

    pipeline = SecurityCheckPipeline([failing_check])
    result = await pipeline.execute(MagicMock())

    assert result is None
    failing_check.create_error_response.assert_not_called()


@pytest.mark.asyncio
async def test_pipeline_fails_open_on_redis_error_without_logging_when_muted() -> None:
    """Fail-open still happens for a muted check, but the skip is not logged."""
    failing_check = _redis_failing_check(
        SecurityConfig(fail_secure=True, redis_fail_open=True)
    )

    pipeline = SecurityCheckPipeline([failing_check], muted_check_logs={"ip_security"})
    logger = MagicMock()
    pipeline.logger = logger

    result = await pipeline.execute(MagicMock())

    assert result is None
    failing_check.create_error_response.assert_not_called()
    logger.warning.assert_not_called()


@pytest.mark.asyncio
async def test_pipeline_blocks_on_redis_error_when_fail_open_disabled() -> None:
    failing_check = _redis_failing_check(
        SecurityConfig(fail_secure=True, redis_fail_open=False)
    )

    pipeline = SecurityCheckPipeline([failing_check])
    result = await pipeline.execute(MagicMock())

    assert result == "BLOCKED"
