import time

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class CloudIpRefreshCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "cloud_ip_refresh"

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        if not self.config.block_cloud_providers:
            return None

        providers = self.config.block_cloud_providers
        has_any_ranges = any(
            cloud_handler.ip_ranges.get(provider) for provider in providers
        )

        if self.config.lazy_init and not has_any_ranges:
            cloud_handler.refresh_async(
                providers, ttl=self.config.cloud_ip_refresh_interval
            )
            self.middleware.last_cloud_ip_refresh = int(time.time())
            return None

        if (
            time.time() - self.middleware.last_cloud_ip_refresh
            > self.config.cloud_ip_refresh_interval
        ):
            self.middleware.refresh_cloud_ip_ranges()
        return None
