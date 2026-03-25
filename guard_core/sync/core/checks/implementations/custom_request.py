from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class CustomRequestCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "custom_request"

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        if not self.config.custom_request_check:
            return None

        custom_response = self.config.custom_request_check(request)
        if custom_response:
            self.middleware.event_bus.send_middleware_event(
                event_type="custom_request_check",
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
                    self.middleware.response_factory.apply_modifier(custom_response)
                )
                return modified
        return None
