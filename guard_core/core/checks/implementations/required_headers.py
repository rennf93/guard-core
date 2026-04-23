from guard_core.core.checks.base import SecurityCheck
from guard_core.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity


def _classify_header_violation(header_name: str) -> tuple[str, str]:
    header_lower = header_name.lower()

    if header_lower == "x-api-key":
        return "authentication", "api_key_required"
    if header_lower == "authorization":
        return "authentication", "required_header"
    return "advanced", "required_header"


class RequiredHeadersCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "required_headers"

    async def _handle_missing_header(
        self, request: GuardRequest, header: str
    ) -> GuardResponse | None:
        reason = f"Missing required header: {header}"

        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=reason,
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
        )

        decorator_type, violation_type = _classify_header_violation(header)

        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_DECORATOR_VIOLATION,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=reason,
            decorator_type=decorator_type,
            violation_type=violation_type,
            missing_header=header,
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=400,
                default_message=reason,
            )
        return None

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)

        if not route_config or not route_config.required_headers:
            return None

        for header, expected in route_config.required_headers.items():
            if expected == "required" and not request.headers.get(header):
                return await self._handle_missing_header(request, header)

        return None
