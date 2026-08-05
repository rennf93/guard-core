from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks import build_default_pipeline
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


def _custom_check(request: SyncGuardRequest) -> GuardResponse | None:
    return None


def _custom_validator(request: SyncGuardRequest) -> GuardResponse | None:
    return None


def _fully_enabled_config() -> SecurityConfig:
    return SecurityConfig(
        emergency_mode=True,
        enforce_https=True,
        log_request_level="INFO",
        block_cloud_providers={"AWS"},
        blocked_user_agents=["badbot"],
        custom_request_check=_custom_check,
    )


def _fully_enabled_route_config() -> RouteConfig:
    route_config = RouteConfig()
    route_config.max_request_size = 1000
    route_config.required_headers = {"X-Api-Key": "required"}
    route_config.auth_required = "bearer"
    route_config.require_referrer = ["example.com"]
    route_config.custom_validators = [_custom_validator]
    route_config.time_restrictions = {"start": "00:00", "end": "23:59"}
    return route_config


@pytest.fixture
def mock_middleware() -> Mock:
    middleware = Mock()
    middleware.config = _fully_enabled_config()
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=500))
    decorator = Mock()
    decorator._route_configs = {"route": _fully_enabled_route_config()}
    middleware.guard_decorator = decorator
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
