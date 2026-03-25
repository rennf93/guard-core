import logging
from datetime import datetime, timezone
from typing import Any

from guard_core.models import SecurityConfig
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import extract_client_ip


class SecurityEventBus:
    def __init__(
        self,
        agent_handler: Any,
        config: SecurityConfig,
        geo_ip_handler: Any = None,
    ):
        self.agent_handler = agent_handler
        self.config = config
        self.geo_ip_handler = geo_ip_handler
        self.logger = logging.getLogger(__name__)

    def send_middleware_event(
        self,
        event_type: str,
        request: SyncGuardRequest,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        if not self.agent_handler or not self.config.agent_enable_events:
            return

        try:
            client_ip = extract_client_ip(request, self.config, self.agent_handler)

            country = None
            if self.geo_ip_handler:
                try:
                    country = self.geo_ip_handler.get_country(client_ip)
                except Exception:
                    pass

            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=client_ip,
                country=country,
                user_agent=request.headers.get("User-Agent"),
                action_taken=action_taken,
                reason=reason,
                endpoint=str(request.url_path),
                method=request.method,
                metadata=kwargs,
            )

            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send security event to agent: {e}")

    def send_https_violation_event(
        self, request: SyncGuardRequest, route_config: RouteConfig | None
    ) -> None:
        https_url = request.url_replace_scheme("https")

        if route_config and route_config.require_https:
            self.send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="https_redirect",
                reason="Route requires HTTPS but request was HTTP",
                decorator_type="authentication",
                violation_type="require_https",
                original_scheme=request.url_scheme,
                redirect_url=https_url,
            )
        else:
            self.send_middleware_event(
                event_type="https_enforced",
                request=request,
                action_taken="https_redirect",
                reason="HTTP request redirected to HTTPS for security",
                original_scheme=request.url_scheme,
                redirect_url=https_url,
            )

    def send_cloud_detection_events(
        self,
        request: SyncGuardRequest,
        client_ip: str,
        cloud_providers_to_check: list[str],
        route_config: RouteConfig | None,
        cloud_handler: Any,
        passive_mode: bool,
    ) -> None:
        cloud_details = cloud_handler.get_cloud_provider_details(
            client_ip, set(cloud_providers_to_check)
        )
        if cloud_details and cloud_handler.agent_handler:
            provider, network = cloud_details
            cloud_handler.send_cloud_detection_event(
                client_ip,
                provider,
                network,
                "request_blocked" if not passive_mode else "logged_only",
            )

        if route_config and route_config.block_cloud_providers:
            self.send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="request_blocked" if not passive_mode else "logged_only",
                reason=f"Cloud provider IP {client_ip} blocked",
                decorator_type="access_control",
                violation_type="cloud_provider",
                blocked_providers=list(cloud_providers_to_check),
            )
