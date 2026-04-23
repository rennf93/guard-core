from guard_core.core.checks.base import SecurityCheck
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import extract_client_ip, log_activity


class EmergencyModeCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "emergency_mode"

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        if not self.config.emergency_mode:
            return None

        client_ip = getattr(request.state, "client_ip", None)
        if not client_ip:
            client_ip = await extract_client_ip(
                request, self.config, self.middleware.agent_handler
            )

        if client_ip not in self.config.emergency_whitelist:
            await log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"[EMERGENCY MODE] Access denied for IP {client_ip}",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
                check_name=self.check_name,
                muted_check_logs=self.config.muted_check_logs,
            )

            await self.middleware.event_bus.send_middleware_event(
                event_type="emergency_mode_block",
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason=f"[EMERGENCY MODE] IP {client_ip} not in whitelist",
                emergency_whitelist_count=len(self.config.emergency_whitelist),
                emergency_active=True,
            )

            if not self.config.passive_mode:
                return await self.middleware.create_error_response(
                    status_code=503,
                    default_message="Service temporarily unavailable",
                )
        else:
            await log_activity(
                request,
                self.logger,
                log_type="info",
                reason=(
                    f"[EMERGENCY MODE] Allowed access for whitelisted IP {client_ip}"
                ),
                level="INFO",
                check_name=self.check_name,
                muted_check_logs=self.config.muted_check_logs,
            )

        return None
