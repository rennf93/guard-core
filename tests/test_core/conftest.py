from collections.abc import Collection
from unittest.mock import AsyncMock, Mock

from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


async def custom_check(request: GuardRequest) -> GuardResponse | None:
    return None


async def custom_validator(request: GuardRequest) -> GuardResponse | None:
    return None


def fully_enabled_route_config() -> RouteConfig:
    route_config = RouteConfig()
    route_config.max_request_size = 1000
    route_config.required_headers = {"X-Api-Key": "required"}
    route_config.auth_required = "bearer"
    route_config.require_referrer = ["example.com"]
    route_config.custom_validators = [custom_validator]
    route_config.time_restrictions = {"start": "00:00", "end": "23:59"}
    return route_config


def fully_enabled_config() -> SecurityConfig:
    return SecurityConfig(
        emergency_mode=True,
        enforce_https=True,
        log_request_level="INFO",
        block_cloud_providers={"AWS"},
        blocked_user_agents=["badbot"],
        custom_request_check=custom_check,
    )


def middleware_for(
    config: SecurityConfig,
    route_configs: Collection[RouteConfig] | None = (),
) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=500))
    if route_configs is None:
        middleware.guard_decorator = None
    else:
        decorator = Mock()
        decorator._route_configs = dict(enumerate(route_configs))
        middleware.guard_decorator = decorator
    return middleware
