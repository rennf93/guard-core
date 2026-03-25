from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.helpers import is_referrer_domain_allowed
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity


class ReferrerCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "referrer"

    def _handle_missing_referrer(
        self, request: SyncGuardRequest, route_config: RouteConfig
    ) -> GuardResponse | None:
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason="Missing referrer header",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        self.middleware.event_bus.send_middleware_event(
            event_type="decorator_violation",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason="Missing referrer header",
            decorator_type="content_filtering",
            violation_type="require_referrer",
            allowed_domains=route_config.require_referrer,
        )

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=403,
                default_message="Referrer required",
            )

        return None

    def _handle_invalid_referrer(
        self, request: SyncGuardRequest, referrer: str, route_config: RouteConfig
    ) -> GuardResponse | None:
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Invalid referrer: {referrer}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        self.middleware.event_bus.send_middleware_event(
            event_type="decorator_violation",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"Referrer '{referrer}' not in allowed domains",
            decorator_type="content_filtering",
            violation_type="require_referrer",
            referrer=referrer,
            allowed_domains=route_config.require_referrer,
        )

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=403,
                default_message="Invalid referrer",
            )

        return None

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)
        if not route_config or not route_config.require_referrer:
            return None

        referrer = request.headers.get("referer", "")

        if not referrer:
            return self._handle_missing_referrer(request, route_config)

        if not is_referrer_domain_allowed(referrer, route_config.require_referrer):
            return self._handle_invalid_referrer(request, referrer, route_config)

        return None
