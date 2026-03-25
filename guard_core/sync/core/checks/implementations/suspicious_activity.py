from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.helpers import detect_penetration_patterns
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity


class SuspiciousActivityCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "suspicious_activity"

    def _handle_suspicious_passive_mode(
        self, request: SyncGuardRequest, client_ip: str, trigger_info: str
    ) -> None:
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Suspicious activity detected: {client_ip}",
            passive_mode=True,
            trigger_info=trigger_info,
            level=self.config.log_suspicious_level,
        )

        message = "Suspicious pattern detected (passive mode)"

        self.middleware.event_bus.send_middleware_event(
            event_type="penetration_attempt",
            request=request,
            action_taken="logged_only",
            reason=f"{message}: {trigger_info}",
            request_count=self.middleware.suspicious_request_counts[client_ip],
            passive_mode=True,
            trigger_info=trigger_info,
        )

    def _handle_suspicious_active_mode(
        self, request: SyncGuardRequest, client_ip: str, trigger_info: str
    ) -> GuardResponse:
        sus_specs = f"{client_ip} - {trigger_info}"

        if (
            self.config.enable_ip_banning
            and self.middleware.suspicious_request_counts[client_ip]
            >= self.config.auto_ban_threshold
        ):
            ip_ban_manager.ban_ip(
                client_ip,
                self.config.auto_ban_duration,
                "penetration_attempt",
            )
            log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"IP banned due to suspicious activity: {sus_specs}",
                level=self.config.log_suspicious_level,
            )

            return self.middleware.create_error_response(
                status_code=403,
                default_message="IP has been banned",
            )

        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Suspicious activity detected for IP: {sus_specs}",
            level=self.config.log_suspicious_level,
        )

        self.middleware.event_bus.send_middleware_event(
            event_type="penetration_attempt",
            request=request,
            action_taken="request_blocked",
            reason=f"Penetration attempt detected: {trigger_info}",
            request_count=self.middleware.suspicious_request_counts[client_ip],
            trigger_info=trigger_info,
        )

        return self.middleware.create_error_response(
            status_code=400,
            default_message="Suspicious activity detected",
        )

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        if getattr(request.state, "is_whitelisted", False):
            return None

        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)

        if not client_ip:
            return None

        detection_result, trigger_info = detect_penetration_patterns(
            request,
            route_config,
            self.config,
            self.middleware.route_resolver.should_bypass_check,
        )

        if trigger_info == "disabled_by_decorator":
            self.middleware.event_bus.send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="detection_disabled",
                reason="Suspicious pattern detection disabled by route decorator",
                decorator_type="advanced",
                violation_type="suspicious_detection_disabled",
            )
            return None

        if not detection_result:
            return None

        self.middleware.suspicious_request_counts[client_ip] = (
            self.middleware.suspicious_request_counts.get(client_ip, 0) + 1
        )

        if self.config.passive_mode:
            self._handle_suspicious_passive_mode(request, client_ip, trigger_info)
            return None

        return self._handle_suspicious_active_mode(request, client_ip, trigger_info)
