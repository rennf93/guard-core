from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.helpers import detect_penetration_patterns
from guard_core.sync.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_PENETRATION_ATTEMPT,
)
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity


class SuspiciousActivityCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "suspicious_activity"

    def _total_count_for_ip(self, client_ip: str) -> int:
        return sum(
            self.middleware.suspicious_request_counts.get(client_ip, {}).values()
        )

    def _increment_per_category(
        self, client_ip: str, threat_categories: list[str]
    ) -> None:
        if client_ip not in self.middleware.suspicious_request_counts:
            self.middleware.suspicious_request_counts[client_ip] = {}
        ip_counts = self.middleware.suspicious_request_counts[client_ip]
        categories = threat_categories or ["uncategorized"]
        for category in categories:
            ip_counts[category] = ip_counts.get(category, 0) + 1

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
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
        )

        message = "Suspicious pattern detected (passive mode)"

        self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="logged_only",
            reason=f"{message}: {trigger_info}",
            request_count=self._total_count_for_ip(client_ip),
            passive_mode=True,
            trigger_info=trigger_info,
        )

    def _try_per_category_ban(
        self,
        request: SyncGuardRequest,
        client_ip: str,
        trigger_info: str,
        threat_categories: list[str],
    ) -> GuardResponse | None:
        if not self.config.enable_ip_banning:
            return None
        ip_counts = self.middleware.suspicious_request_counts.get(client_ip, {})
        sus_specs = f"{client_ip} - {trigger_info}"
        for category in threat_categories:
            entry = self.config.threat_ban_config.get(category)
            if entry is None:
                continue
            if ip_counts.get(category, 0) >= entry.threshold:
                ip_ban_manager.ban_ip(
                    client_ip,
                    entry.duration,
                    f"penetration_attempt:{category}",
                )
                log_activity(
                    request,
                    self.logger,
                    log_type="suspicious",
                    reason=f"IP banned due to {category} threshold: {sus_specs}",
                    level=self.config.log_suspicious_level,
                    check_name=self.check_name,
                    muted_check_logs=self.config.muted_check_logs,
                )
                return self.middleware.create_error_response(
                    status_code=403,
                    default_message="IP has been banned",
                )
        return None

    def _try_flat_ban(
        self,
        request: SyncGuardRequest,
        client_ip: str,
        trigger_info: str,
    ) -> GuardResponse | None:
        if not self.config.enable_ip_banning:
            return None
        total_count = self._total_count_for_ip(client_ip)
        if total_count < self.config.auto_ban_threshold:
            return None
        ip_ban_manager.ban_ip(
            client_ip,
            self.config.auto_ban_duration,
            "penetration_attempt",
        )
        sus_specs = f"{client_ip} - {trigger_info}"
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"IP banned due to suspicious activity: {sus_specs}",
            level=self.config.log_suspicious_level,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
        )
        return self.middleware.create_error_response(
            status_code=403,
            default_message="IP has been banned",
        )

    def _handle_suspicious_active_mode(
        self,
        request: SyncGuardRequest,
        client_ip: str,
        trigger_info: str,
        threat_categories: list[str],
    ) -> GuardResponse:
        per_category_response = self._try_per_category_ban(
            request, client_ip, trigger_info, threat_categories
        )
        if per_category_response is not None:
            return per_category_response

        flat_response = self._try_flat_ban(request, client_ip, trigger_info)
        if flat_response is not None:
            return flat_response

        sus_specs = f"{client_ip} - {trigger_info}"
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Suspicious activity detected for IP: {sus_specs}",
            level=self.config.log_suspicious_level,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
        )

        self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="request_blocked",
            reason=f"Penetration attempt detected: {trigger_info}",
            request_count=self._total_count_for_ip(client_ip),
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

        result = detect_penetration_patterns(
            request,
            route_config,
            self.config,
            self.middleware.route_resolver.should_bypass_check,
        )

        if result.trigger_info == "disabled_by_decorator":
            self.middleware.event_bus.send_middleware_event(
                event_type=EVENT_DECORATOR_VIOLATION,
                request=request,
                action_taken="detection_disabled",
                reason="Suspicious pattern detection disabled by route decorator",
                decorator_type="advanced",
                violation_type="suspicious_detection_disabled",
            )
            return None

        if not result.is_threat:
            return None

        trigger_info = result.trigger_info
        threat_categories = list(result.threat_categories)

        self._increment_per_category(client_ip, threat_categories)

        if self.config.passive_mode:
            self._handle_suspicious_passive_mode(request, client_ip, trigger_info)
            return None

        return self._handle_suspicious_active_mode(
            request, client_ip, trigger_info, threat_categories
        )
