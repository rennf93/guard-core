from unittest.mock import MagicMock

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline


def test_default_security_config_is_fail_secure() -> None:
    config = SecurityConfig()
    assert hasattr(config, "fail_secure")
    assert config.fail_secure is True


def test_fail_secure_can_be_disabled() -> None:
    config = SecurityConfig(fail_secure=False)
    assert config.fail_secure is False


def test_pipeline_returns_blocked_when_fail_secure_and_check_raises() -> None:
    middleware = MagicMock()
    middleware.config = SecurityConfig(fail_secure=True)
    middleware.logger = MagicMock()

    failing_check = MagicMock()
    failing_check.check_name = "boom"
    failing_check.config = middleware.config
    failing_check.is_muted = False
    failing_check.check = MagicMock(side_effect=RuntimeError("boom"))
    failing_check.create_error_response = MagicMock(return_value="BLOCKED")

    pipeline = SecurityCheckPipeline([failing_check])
    result = pipeline.execute(MagicMock())
    assert result == "BLOCKED"


def test_pipeline_falls_through_when_not_fail_secure() -> None:
    middleware = MagicMock()
    middleware.config = SecurityConfig(fail_secure=False)
    middleware.logger = MagicMock()

    failing_check = MagicMock()
    failing_check.check_name = "boom"
    failing_check.config = middleware.config
    failing_check.is_muted = False
    failing_check.check = MagicMock(side_effect=RuntimeError("boom"))

    pipeline = SecurityCheckPipeline([failing_check])
    result = pipeline.execute(MagicMock())
    assert result is None
