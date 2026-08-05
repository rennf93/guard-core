from collections.abc import Collection

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.helpers import (
    check_user_agent_allowed,
    route_config_applies,
)
from guard_core.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_USER_AGENT_BLOCKED,
)
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity


class UserAgentCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "user_agent"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return (
            bool(config.blocked_user_agents)
            or route_config_applies(
                route_configs, lambda rc: bool(rc.blocked_user_agents)
            )
            or config.enable_dynamic_rules
        )

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        if getattr(request.state, "is_whitelisted", False):
            return None

        route_config = getattr(request.state, "route_config", None)
        user_agent = request.headers.get("User-Agent", "")

        if not await check_user_agent_allowed(user_agent, route_config, self.config):
            await log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"Blocked user agent: {user_agent}",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
                check_name=self.check_name,
                muted_check_logs=self.config.muted_check_logs,
            )

            if route_config and route_config.blocked_user_agents:
                await self.middleware.event_bus.send_middleware_event(
                    event_type=EVENT_DECORATOR_VIOLATION,
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"User agent '{user_agent}' blocked",
                    decorator_type="access_control",
                    violation_type="user_agent",
                    blocked_user_agent=user_agent,
                )
            else:
                await self.middleware.event_bus.send_middleware_event(
                    event_type=EVENT_USER_AGENT_BLOCKED,
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"User agent '{user_agent}' in global blocklist",
                    user_agent=user_agent,
                    filter_type="global",
                )

            if not self.config.passive_mode:
                return await self.middleware.create_error_response(
                    status_code=403,
                    default_message="User-Agent not allowed",
                )
        return None
