from datetime import datetime, timezone
from ipaddress import ip_address, ip_network

from guard_core.sync.core.validation.context import ValidationContext
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class RequestValidator:
    def __init__(self, context: ValidationContext) -> None:
        self.context = context

    def is_request_https(self, request: SyncGuardRequest) -> bool:
        is_https = request.url_scheme == "https"

        if (
            self.context.config.trust_x_forwarded_proto
            and self.context.config.trusted_proxies
            and request.client_host
        ):
            if self.is_trusted_proxy(request.client_host):
                forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
                is_https = is_https or forwarded_proto.lower() == "https"

        return is_https

    def is_trusted_proxy(self, connecting_ip: str) -> bool:
        for proxy in self.context.config.trusted_proxies:
            if "/" not in proxy:
                if connecting_ip == proxy:
                    return True
            else:
                if ip_address(connecting_ip) in ip_network(proxy, strict=False):
                    return True
        return False

    def check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        try:
            start_time = time_restrictions["start"]
            end_time = time_restrictions["end"]

            current_time = datetime.now(timezone.utc)
            current_hour_minute = current_time.strftime("%H:%M")

            if start_time > end_time:
                return (
                    current_hour_minute >= start_time or current_hour_minute <= end_time
                )
            else:
                return start_time <= current_hour_minute <= end_time

        except Exception as e:
            self.context.logger.error(f"Error checking time window: {e!s}")
            return True

    def is_path_excluded(self, request: SyncGuardRequest) -> bool:
        if any(
            request.url_path.startswith(path)
            for path in self.context.config.exclude_paths
        ):
            self.context.event_bus.send_middleware_event(
                event_type="path_excluded",
                request=request,
                action_taken="security_checks_bypassed",
                reason=f"Path {request.url_path} excluded from security checks",
                excluded_path=request.url_path,
                configured_exclusions=self.context.config.exclude_paths,
            )
            return True
        return False
