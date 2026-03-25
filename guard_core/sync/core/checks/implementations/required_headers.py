from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity


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

    def _handle_missing_header(
        self, request: SyncGuardRequest, header: str
    ) -> GuardResponse | None:
        reason = f"Missing required header: {header}"

        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=reason,
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        decorator_type, violation_type = _classify_header_violation(header)

        self.middleware.event_bus.send_middleware_event(
            event_type="decorator_violation",
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
            return self.middleware.create_error_response(
                status_code=400,
                default_message=reason,
            )
        return None

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)

        if not route_config or not route_config.required_headers:
            return None

        for header, expected in route_config.required_headers.items():
            if expected == "required" and not request.headers.get(header):
                return self._handle_missing_header(request, header)

        return None
