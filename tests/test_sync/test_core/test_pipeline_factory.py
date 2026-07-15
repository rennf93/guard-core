from unittest.mock import MagicMock, Mock

import pytest

from guard_core.sync.core.checks import build_default_pipeline


@pytest.fixture
def mock_middleware() -> Mock:
    middleware = Mock()
    middleware.config = Mock()
    middleware.config.fail_secure = False
    middleware.config.passive_mode = False
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=500))
    return middleware


def test_default_pipeline_contains_all_checks_in_canonical_order(
    mock_middleware: Mock,
) -> None:
    pipeline = build_default_pipeline(mock_middleware)
    assert pipeline.get_check_names() == [
        "route_config",
        "emergency_mode",
        "https_enforcement",
        "request_logging",
        "request_size_content",
        "required_headers",
        "authentication",
        "referrer",
        "custom_validators",
        "time_window",
        "cloud_ip_refresh",
        "ip_security",
        "cloud_provider",
        "user_agent",
        "rate_limit",
        "suspicious_activity",
        "custom_request",
    ]


def test_default_pipeline_builds_fresh_check_instances_per_call(
    mock_middleware: Mock,
) -> None:
    first = build_default_pipeline(mock_middleware)
    second = build_default_pipeline(mock_middleware)
    assert first.checks[0] is not second.checks[0]
