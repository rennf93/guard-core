from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity


class CloudProviderCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "cloud_provider"

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        if getattr(request.state, "is_whitelisted", False):
            return None

        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)
        if not client_ip:
            return None

        if self.middleware.route_resolver.should_bypass_check("clouds", route_config):
            return None

        cloud_providers_to_check = (
            self.middleware.route_resolver.get_cloud_providers_to_check(route_config)
        )
        if not cloud_providers_to_check:
            return None

        if not cloud_handler.is_cloud_ip(client_ip, set(cloud_providers_to_check)):
            return None

        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Blocked cloud provider IP: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        self.middleware.event_bus.send_cloud_detection_events(
            request,
            client_ip,
            cloud_providers_to_check,
            route_config,
            cloud_handler,
            self.config.passive_mode,
        )

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=403,
                default_message="Cloud provider IP not allowed",
            )

        return None
