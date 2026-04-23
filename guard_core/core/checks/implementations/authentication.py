from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.helpers import validate_auth_header
from guard_core.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.decorators.base import RouteConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity


class AuthenticationCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "authentication"

    async def _handle_auth_failure(
        self, request: GuardRequest, auth_reason: str, route_config: RouteConfig
    ) -> GuardResponse | None:
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Authentication failure: {auth_reason}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
        )

        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_DECORATOR_VIOLATION,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=auth_reason,
            decorator_type="authentication",
            violation_type="require_auth",
            auth_type=route_config.auth_required,
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=401,
                default_message="Authentication required",
            )

        return None

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)
        if not route_config or not route_config.auth_required:
            return None

        auth_header = request.headers.get("authorization", "")

        is_valid, auth_reason = validate_auth_header(
            auth_header, route_config.auth_required
        )

        if not is_valid:
            return await self._handle_auth_failure(request, auth_reason, route_config)

        return None
