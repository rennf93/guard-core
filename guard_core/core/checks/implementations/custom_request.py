from collections.abc import Collection

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.events.event_types import EVENT_CUSTOM_REQUEST_CHECK
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class CustomRequestCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "custom_request"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return config.custom_request_check is not None

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        if not self.config.custom_request_check:
            return None

        custom_response = await self.config.custom_request_check(request)
        if custom_response:
            await self.middleware.event_bus.send_middleware_event(
                event_type=EVENT_CUSTOM_REQUEST_CHECK,
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason="Custom request check returned blocking response",
                response_status=custom_response.status_code
                if hasattr(custom_response, "status_code")
                else "unknown",
                check_function=self.config.custom_request_check.__name__
                if hasattr(self.config.custom_request_check, "__name__")
                else "anonymous",
            )

            if not self.config.passive_mode:
                modified: GuardResponse = (
                    await self.middleware.response_factory.apply_modifier(
                        custom_response
                    )
                )
                return modified
        return None
