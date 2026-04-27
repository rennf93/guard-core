from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.models import SecurityConfig


def test_fail_secure_field_exists_with_safe_default() -> None:
    config = SecurityConfig()
    assert hasattr(config, "fail_secure")
    assert config.fail_secure is False


def test_fail_secure_can_be_enabled() -> None:
    config = SecurityConfig(fail_secure=True)
    assert config.fail_secure is True


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
